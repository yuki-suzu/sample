# PostgreSQL 超巨大パーティションテーブルのカラム追加（物理並び順維持・再構築）ナレッジ

* **対象バージョン:** PostgreSQL 16.x（16.2にて検証）
* **想定ケース:** 総件数1億件超、特定の子パーティション（都道府県別など）に最大3,000万件規模の偏りがあるパーティションテーブルに対して、**既存のカラム並び順を維持したまま途中に新規カラムを追加する**。

---

## 1. 設計方針：なぜ「全件退避 → 再作成 → 復元」ではなく「子パーティション単位のローリング移行」なのか？

PostgreSQLの `ALTER TABLE ... ADD COLUMN` は論理的・物理的に必ずテーブルの末尾へカラムが追加される仕様である。物理的なカラム順序を途中に挿入・維持するにはテーブルの再作成が必須となるが、1億件超のテーブルを一括で退避・復元すると以下の重大なリスクが発生する。

| 比較項目 | × 非推奨：一括退避・復元方式 | ◎ 採用：子パーティション単位のローリング移行方式 |
|---|---|---|
| **必要な空きディスク容量** | **元テーブルの100%以上**（退避データ＋新テーブル） | **最大の子パーティション1個分（3,000万件分）のみ** |
| **データI/OとWAL発生量** | **2往復分**（退避時＋復元時で倍増・WAL枯渇リスク大） | **片道1回のみ**（旧子テーブルから新子テーブルへ直接コピー） |
| **メモリ（OOM）リスク** | 1億件一括処理・インデックス更新で高負荷 | ストリーム投入＋最後に子単位でインデックス構築するため**極小** |
| **タプル振り分け負荷** | 親経由でINSERTすると1億回のルーティング計算が発生 | **子から子へ直接INSERTするためルーティング負荷ゼロ** |
| **途中失敗時のリカバリ** | 復元途中で失敗すると最初からやり直し | **失敗した都道府県のパーティション1個から即座に再開可能** |

### 最大3,000万件（東京都など）の巨大パーティションを乗り切る3大鉄則
1. **主キー（PK）・インデックスは「データ移行がすべて終わった最後」に一括で貼る**
   親テーブルや子テーブルにインデックスがある状態で3,000万件を `INSERT` すると、B-Treeの更新とWAL出力で処理時間が数倍に膨れ上がる。移行中は「インデックスなし」の状態でデータのみを流し込む。
2. **1パーティション移行するごとに旧パーティションを即座に `DROP` する**
   移行が完了した旧子パーティションをその場で削除することで、常に「1パーティション分の空き容量」だけで1億件すべての移行を完遂できる。
3. **1パーティションごとに `COMMIT` し、直後に手動 `CHECKPOINT` を実行する**
   3,000万件分のトランザクションをコミットした直後に `CHECKPOINT;` を明示的に走らせることで、不要になった大量のWALファイルを即座にリサイクル（削除・再利用）させ、`pg_wal` ディレクトリのパンクを防ぐ。

---

## 2. 事前準備（移行前の情報控えと空き容量チェック）

テーブルを作り直すため、旧親テーブルに設定されている「インデックス定義」「外部キー制約」「シーケンスの現在値」を事前に取得してテキストファイル等に控えておくこと。

### ① 必要な空きディスク容量の確認（目安：最大パーティションの約1.5〜2倍）
以下のSQLで、最も大きい子パーティション（例：3,000万件のパーティション）の物理サイズを確認する。そのサイズと同等以上の空き容量がデータ領域およびWAL領域にあれば安全に実行できる。

```sql
/**
 * 子パーティションごとの概算件数と物理ディスクサイズを大きい順に表示する確認クエリ
 */
SELECT 
    nmsp_child.nspname AS schema_name,
    child.relname AS partition_name,
    to_char(child.reltuples, 'FM999,999,999,999') AS est_rows,
    pg_size_pretty(pg_relation_size(child.oid)) AS table_size,
    pg_size_pretty(pg_indexes_size(child.oid)) AS index_size,
    pg_size_pretty(pg_total_relation_size(child.oid)) AS total_size
FROM pg_inherits inh
JOIN pg_class parent ON inh.inhparent = parent.oid
JOIN pg_namespace nmsp_parent ON parent.relnamespace = nmsp_parent.oid
JOIN pg_class child ON inh.inhrelid = child.oid
JOIN pg_namespace nmsp_child ON child.relnamespace = nmsp_child.oid
WHERE nmsp_parent.nspname = 'public'      -- ★対象スキーマ名に変更
  AND parent.relname = 'pref_data'        -- ★対象の親テーブル名に変更
ORDER BY pg_total_relation_size(child.oid) DESC;
```

### ② 親テーブルの主キー・インデックス・外部キー再作成用DDLの事前抽出
移行完了後に一括で復元するため、現在の親テーブル（および他テーブルから参照されている外部キー）のDDLを抽出して保存しておく。

```sql
/**
 * 親テーブルに定義されている制約（PK/UNIQUE/FK）およびインデックスの再作成用DDLを抽出するクエリ
 */
WITH target_parent AS (
    SELECT c.oid AS relid, n.nspname AS schema_name, c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'     -- ★対象スキーマ名
      AND c.relname = 'pref_data'  -- ★対象の親テーブル名
)
-- 1. 親テーブル自身の制約（PK / UNIQUE / FK / CHECK）と、他テーブルからこの親を参照しているFK
SELECT 'CONSTRAINT' AS obj_type,
       format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s;', ns.nspname, cl.relname, con.conname, pg_get_constraintdef(con.oid)) AS restore_ddl
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_namespace ns ON ns.oid = cl.relnamespace
WHERE con.conrelid IN (SELECT relid FROM target_parent)
   OR con.confrelid IN (SELECT relid FROM target_parent)
UNION ALL
-- 2. 親テーブルに定義されているセカンダリインデックス（PK/UNIQUE制約の裏で作られたものは除く）
SELECT 'INDEX' AS obj_type,
       pg_get_indexdef(i.indexrelid) || ';' AS restore_ddl
FROM target_parent t
JOIN pg_index i ON i.indrelid = t.relid
LEFT JOIN pg_constraint con ON con.conindid = i.indexrelid
WHERE con.oid IS NULL;
```

---

## 3. 実践ステップ（全5工程）

### Step 1：新しいカラム並び順で「新・親テーブル（仮名）」を作成する
現行の親テーブルは残したまま、別名（末尾に `_new`）で新しいカラム順の親テーブルを作成する。
* **重要:** この時点では **`PRIMARY KEY` や `CREATE INDEX`、外部キー制約は一切付与しない** こと（`NOT NULL` 制約や `DEFAULT` 値は付与してよい）。

```sql
-- 例：pref_code の直後に new_col を追加した新しい親テーブルを作成（PK・Indexはまだ貼らない！）
CREATE TABLE public.pref_data_new (
    id          BIGINT NOT NULL,
    pref_code   CHAR(2) NOT NULL,
    new_col     VARCHAR(50) DEFAULT 'INIT', -- ★希望の位置に追加した新カラム
    user_name   VARCHAR(100) NOT NULL,
    created_at  TIMESTAMP NOT NULL
) PARTITION BY LIST (pref_code);
```

---

### Step 2：子パーティション単位のローリング移行SQLを自動生成する
以下のクエリを実行すると、既存の全子パーティションの境界値（`FOR VALUES IN (...)` 等）を自動で読み取り、**件数が少ない県から順番に（最大の3,000万件パーティションを最後に）** 安全に移行するSQLスクリプトが一括生成される。

* `params` 内の `target_schema`, `old_parent_name`, `new_parent_name`, `select_clause` を環境に合わせて書き換えて実行すること。

```sql
/**
 * 旧親テーブルの既存カラム一覧をシステムカタログから自動取得し、
 * 新規追加カラムには新テーブル側の DEFAULT 値（またはNULL）が自動適用される形で
 * 子パーティション単位のローリング移行SQLを自動生成するクエリ（カラム手書き不要版）
 *
 * @param target_schema   対象スキーマ名
 * @param old_parent_name 現行の親テーブル名
 * @param new_parent_name 新しく作成した親テーブルの仮名（新カラムにDEFAULT定義済みの状態）
 * @return パーティションごとの移行ステップSQL（件数の少ない順）
 */
WITH params AS (
    SELECT 
        'public'::text            AS target_schema,
        'pref_data'::text         AS old_parent_name,
        'pref_data_new'::text     AS new_parent_name
        -- ★ SELECT句の手書き指定は不要！旧親テーブルのカラムを自動抽出します
),
-- 旧親テーブルから既存の全カラム名（生成列を除く）を定義順でカンマ区切り取得
old_columns AS (
    SELECT 
        string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) AS col_list
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid
    CROSS JOIN params p
    WHERE n.nspname = p.target_schema
      AND c.relname = p.old_parent_name
      AND a.attnum > 0 
      AND NOT a.attisdropped
      AND a.attgenerated = '' -- GENERATED ALWAYS AS の計算列は自動除外
),
partitions AS (
    SELECT 
        nmsp_child.nspname  AS child_schema,
        child.relname       AS old_child_name,
        child.relname || '_new' AS new_child_name,
        pg_get_expr(child.relpartbound, child.oid) AS part_bound_expr,
        child.reltuples::bigint AS est_rows
    FROM pg_inherits inh
    JOIN pg_class parent ON inh.inhparent = parent.oid
    JOIN pg_namespace nmsp_parent ON parent.relnamespace = nmsp_parent.oid
    JOIN pg_class child ON inh.inhrelid = child.oid
    JOIN pg_namespace nmsp_child ON child.relnamespace = nmsp_child.oid
    CROSS JOIN params p
    WHERE nmsp_parent.nspname = p.target_schema
      AND parent.relname = p.old_parent_name
    ORDER BY child.reltuples ASC, child.relname
)
SELECT 
    format(
$SQL$-- =================================================================
-- パーティション移行: %1$I.%2$I (概算: %7$s 件)
-- =================================================================
BEGIN;
SET LOCAL synchronous_commit = off;

-- 1. 新しい子パーティションを作成（親テーブルのDEFAULT定義も自動で引き継がれる）
CREATE TABLE %1$I.%3$I PARTITION OF %1$I.%4$I %5$s;

-- 2. 旧テーブルに存在するカラムだけを指定してINSERT（新カラムは指定しないため自動的にDEFAULT値が入る！）
INSERT INTO %1$I.%3$I (%6$s)
SELECT %6$s FROM %1$I.%2$I;

-- 3. 移行が終わった旧子パーティションを即座にDROPして物理ディスク領域を解放
DROP TABLE %1$I.%2$I;

-- 4. 新子パーティションを本来の名前にリネーム
ALTER TABLE %1$I.%3$I RENAME TO %2$I;
COMMIT;

CHECKPOINT;
$SQL$,
        pt.child_schema,
        pt.old_child_name,
        pt.new_child_name,
        p.new_parent_name,
        pt.part_bound_expr,
        oc.col_list,
        to_char(GREATEST(pt.est_rows, 0), 'FM999,999,999,999')
    ) AS rolling_migration_sql
FROM partitions pt
CROSS JOIN params p
CROSS JOIN old_columns oc;
```

---

### Step 3：生成されたローリング移行SQLを実行する
Step 2で出力されたSQLを `psql` 等で実行する（または生成クエリの直後に `\gexec` で実行する）。
* まずは先頭の1県分だけを実行し、正常に移行・旧テーブルDROP・リネームが行われることを確認してから残りの全県を流すとより確実である。

---

### Step 4：親テーブルの切り替え（旧親テーブル削除 ＆ リネーム）
全47都道府県の移行が完了すると、旧親テーブル（`pref_data`）は子パーティションを持たない空の殻になっている。ここで旧親テーブルを削除し、新親テーブルを本来の名前にリネームする。

> **⚠️ シーケンス（`SERIAL` / `IDENTITY`）や他テーブルからの外部キーがある場合の注意**
> 旧親テーブルを `DROP TABLE ... CASCADE` で消すと、旧親テーブルが所有していたシーケンスや、他テーブルからの外部キーも消える。
> * `IDENTITY` 列や `SERIAL` 列を使っている場合は、新親テーブル作成時にも定義しておくか、`ALTER SEQUENCE シーケンス名 OWNED BY public.pref_data_new.id;` で所有権を新親テーブルへ移してから旧親テーブルをDROPすること。

```sql
BEGIN;
-- 中身が空になった旧・親テーブルを削除
DROP TABLE public.pref_data CASCADE;

-- 新・親テーブルを本来のテーブル名にリネーム
ALTER TABLE public.pref_data_new RENAME TO pref_data;
COMMIT;
```

---

### Step 5：主キー・インデックスの一括作成と統計情報更新（`ANALYZE`）
最後に、メモリと並列ワーカー数を最大限に割り当てた状態で、事前準備②で控えておいた **親テーブルに対する `ADD PRIMARY KEY` や `CREATE INDEX` を一括実行** する。

* PostgreSQL 16では、親テーブルに対して `CREATE INDEX` や `ADD PRIMARY KEY` を実行すると、**内部的に47個の子パーティションに対して1つずつ順番にインデックスを構築していく**。
* 1億件全体を一度にソートするのではなく「最大でも1パーティション（3,000万件）単位のソート」になるため、`maintenance_work_mem = '2GB'`（余裕があれば `'4GB'`）を設定しておけばメモリ不足（OOM）は一切発生せず、Bloat（肥大化）ゼロの綺麗なインデックスが高速に構築される。

```sql
-- 1. インデックス高速構築用のセッションパラメータ設定
SET maintenance_work_mem = '2GB';          -- サーバーの空きメモリに応じて 2GB〜4GB を指定
SET max_parallel_maintenance_workers = 4;  -- CPUコア数に応じて 2〜8 を指定

-- 2. 主キー・ユニーク制約・セカンダリインデックス・外部キーの一括付与（事前準備②で控えたDDLを実行）
ALTER TABLE public.pref_data ADD PRIMARY KEY (id, pref_code);
CREATE INDEX idx_pref_data_user_name ON public.pref_data (user_name);
CREATE INDEX idx_pref_data_created_at ON public.pref_data (created_at);

-- 3. シーケンス（SERIAL / IDENTITY）を使用している場合は最大値に同期
SELECT setval(
    pg_get_serial_sequence('public.pref_data', 'id'),
    COALESCE((SELECT MAX(id) FROM public.pref_data), 1),
    (SELECT MAX(id) IS NOT NULL FROM public.pref_data)
);

-- 4. 最後に統計情報を更新して完了！（これを行わないと実行計画が狂うため必須）
ANALYZE public.pref_data;
```

---

## 4. 作業前後の確認チェックリスト

- [ ] **【作業前】** 事前準備①のSQLで、最大パーティション（3,000万件）のテーブルサイズ以上の空き容量がディスクにあることを確認したか？
- [ ] **【作業前】** 事前準備②のSQLで、親テーブルの主キー・インデックス・外部キーの定義、および対象テーブルに対する `GRANT`（権限）設定を控えたか？
- [ ] **【作業中】** Step 1で新親テーブルを作る際、主キーとインデックスを「貼らずに」作成したか？
- [ ] **【作業後】** `\d+ テーブル名` で、追加したカラムが意図通りの並び順に入っており、全47都道府県のパーティションが紐づいていることを確認したか？
- [ ] **【作業後】** 主キー・インデックス・権限（`GRANT`）・シーケンスの現在値が元通り復元され、最後に `ANALYZE` を実行したか？
