# PostgreSQL メンテナンス（pg_repack）＆ 超巨大データ高速移行ナレッジ

* **対象バージョン:** PostgreSQL 16.x（16.2にて検証）
* **目的:** テーブル肥大化（Bloat）対策の判断基準の統一、およびスキーマ間・サーバー間での超巨大テーブル移行手順の標準化

---

## 第1部：`pg_repack` と `fillfactor` 運用ガイド

### 1. `pg_repack` の概要と標準コマンドとの違い
`pg_repack` は、PostgreSQLのテーブルやインデックスの肥大化（Bloat）を、**長時間の強い排他ロック（`AccessExclusiveLock`）をかけずにオンラインのまま解消し、未使用の物理ディスク領域をOSへ返却する**拡張機能である。

| コマンド / ツール | 空き領域のOS返却 | 物理順序の並び替え | 処理中のテーブルロック | 実行中の参照・更新（SELECT / DML） |
|---|---|---|---|---|
| **通常の `VACUUM`** | 不可（DB内で再利用のみ） | 不可 | なし | **可能** |
| **`VACUUM FULL`** | **可能** | 不可 | **終始強い排他ロック** | 不可（完了まで完全停止） |
| **`CLUSTER`** | **可能** | **可能** | **終始強い排他ロック** | 不可（完了まで完全停止） |
| **`pg_repack`** | **可能** | **可能** | **最初と最後の一瞬のみ** | **可能（オンライン実行）** |

#### `pg_repack` で実現できる4つの機能
1. **オンラインでのテーブル領域圧縮（`VACUUM FULL` 相当）:** `-n`（`--no-order`）オプションによりソートを省き高速に領域を引き締める。
2. **オンラインでの物理データ並び替え（`CLUSTER` 相当）:** `-o`（`--order-by`）やクラスターインデックス順で物理配置を整理し、範囲検索時のI/O効率を向上させる。
3. **インデックスのみのオンライン再構築（`REINDEX` 相当）:** `-x`（`--only-indexes`）や `-i`（`--index`）でインデックスのみを再構築する。`-j` による並列処理が可能。
4. **別テーブル空間（Tablespace）へのオンライン移動:** `-s`（`--tablespace`）等で物理ストレージ間をオンライン移動する（※スキーマ間の移動ではない点に注意）。

#### 導入・運用上の必須制約
* **主キー（PK）または NOT NULL な UNIQUE インデックスが必須**（`-x` によるインデックスのみの再構築を除く）。
* **空きディスク容量が「対象テーブル＋インデックスの最大約2倍」必要**（内部で新しい作業用テーブルを作成して最後にスワップするため）。
* **玉突きロック対策が必須:** 最初（トリガー作成時）と最後（テーブルスワップ時）の一瞬だけ `AccessExclusiveLock` を取得する。長時間トランザクションと競合すると後続クエリがすべて詰まるため、本番実行時は `-T`（待機タイムアウト）や `-D`（他セッションをキルしない）の指定を推奨する。

---

### 2. 統計情報の更新（`ANALYZE`）の要否
* **結論:** 手動での `ANALYZE` は**原則不要**。`pg_repack` はテーブルスワップ完了直後に**自動で `ANALYZE` を実行する**。
* **例外的に手動対応や注意が必要なケース:**
  1. **`-Z`（`--no-analyze`）を指定した場合:** 実行時間短縮や統計情報固定のためにスキップした場合は、事後に手動で `ANALYZE` を実行すること。
  2. **`-x` / `-i` でインデックスのみ再構築した場合:** 自動 `ANALYZE` は走らない。通常のB-Treeインデックスなら不要だが、**関数インデックス（式インデックス）** を再構築した際は手動 `ANALYZE` を推奨。

---

### 3. テーブル特性別の `pg_repack` 要否判定と `fillfactor` 設計
PostgreSQLの `UPDATE` は、内部的には「旧行に削除マーク（Dead Tuple）を付け、新行を `INSERT` する」追記型モデル（MVCC）であるため、`DELETE` がなくても `UPDATE` が多いテーブルは肥大化する。

| テーブルの特性・規模 | `pg_repack` の要否 | 判定理由・対策方針 |
|---|---|---|
| **数十万件以上 × `DELETE` + `INSERT`** | **◎ 必須候補** | 大量の空き領域（Dead Tuple）が発生するため最も効果が高い。 |
| **数十万件以上 × `INSERT` + 一部 `UPDATE`** | **◯ 条件付きで必要** | 更新頻度（バッチ大量更新か都度更新か）と、**更新カラムにインデックスがあるか（HOT更新の成否）**で決まる。 |
| **最大数万件程度のマスタ系テーブル** | **△ 原則不要** | 数MB〜数十MB程度であれば全て共有バッファ（メモリ）に乗るため、ロックリスクを冒すメリットがない。 |
| **`INSERT` のみ（更新・削除なし）** | **× 原則不要** | Dead Tupleが発生しないためサイズは縮まらない。検索高速化はカバリングインデックスやパーティショニングで対応する。 |

#### `fillfactor` と HOT（Heap-Only Tuple）更新の関係
* **非インデックス項目が更新される場合（テーブルの `fillfactor` が絶大な効果を発揮）:**
  テーブルの `fillfactor` をデフォルトの `100` から `80`〜`90` に下げて8KBページ内に空きを確保しておくと、同一ページ内で更新が完結する **HOT更新** が成立する。インデックスへの追記が一切発生せず、ページ内のミニ掃除（Pruning）だけで領域が再利用されるため、テーブルもインデックスも肥大化しなくなる。
* **インデックス項目が更新される場合:**
  インデックスのキー自体が変わるためHOT更新にはならず、インデックス側は肥大化する。ただし、テーブルの `fillfactor` を下げておけば「新タプルが別ページへ飛ばされて物理的な並び順（`correlation`）が崩壊すること」は防げる。また、インデックス側の肥大化を抑えるには **インデックス自体の `fillfactor`（デフォルト `90`）を `70`〜`80` に下げる** アプローチが有効。

#### 【診断用SQL】各テーブルのHOT更新率とDead Tupleの確認
```sql
SELECT
    relname AS table_name,
    n_tup_upd AS total_updates,
    n_tup_hot_upd AS hot_updates,
    ROUND((n_tup_hot_upd::numeric / NULLIF(n_tup_upd, 0)) * 100, 2) AS hot_update_ratio_pct,
    n_dead_tup AS current_dead_tuples
FROM
    pg_stat_user_tables
WHERE
    n_tup_upd > 1000
ORDER BY
    n_tup_upd DESC;
```

---

## 第2部：超巨大テーブルの別スキーマ・別サーバーへの高速データ移行

既に移行先スキーマにテーブル構造が存在する状態で、超巨大データを高速に移行する標準手順。
以下の3つの競合制御モード（`mode`）をパラメータ1つで切り替え可能としている。

* **`ignore`（既存を残す）:** 主キー重複時はエラーにせずスキップ（`ON CONFLICT DO NOTHING`）
* **`overwrite`（上書きする）:** 主キー重複時は非主キー項目を移行元データで更新（`ON CONFLICT DO UPDATE`）
* **`truncate`（事前に空にする）:** 移行先を `TRUNCATE` してから全件高速投入

> **💡 自動生成スクリプト共通の仕様**
> * 複合主キーの自動展開に対応。
> * PostgreSQLの生成列（`GENERATED ALWAYS AS`）はINSERT/UPDATE対象から自動除外。
> * 全カラムが主キーの構成（中間テーブル等）で `overwrite` を指定した場合、構文エラーを防ぐため自動で `DO NOTHING` にフォールバックする。

---

### 1. 【案1】同一DB内（`db1` → `db2`）のデータ移行SQL自動生成クエリ
`psql` で実行後、直後に `\gexec` を実行すると生成されたSQLをそのまま一括実行できる。

```sql
/**
 * 案1: 同一DB内の別スキーマへ全量データ移行するSQLの自動生成クエリ
 * 
 * @param src_schema    移行元スキーマ名 (例: 'db1')
 * @param dst_schema    移行先スキーマ名 (例: 'db2')
 * @param table_pattern 対象テーブルのLIKE条件 ('%' で全テーブル, 'ese%' で特定テーブル)
 * @param mode          競合時の挙動 ('ignore': 既存を残す, 'overwrite': 上書きする, 'truncate': 事前に空にする)
 * @return 実行可能なデータ移行用SQL文のリスト
 */
WITH params AS (
    SELECT 
        'db1'::text       AS src_schema,
        'db2'::text       AS dst_schema,
        'ese%'::text      AS table_pattern, -- 全テーブルなら '%' に変更
        'overwrite'::text AS mode           -- 'ignore' | 'overwrite' | 'truncate'
),
target_tables AS (
    SELECT 
        c.oid AS relid,
        c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN params p
    WHERE n.nspname = p.src_schema
      AND c.relkind = 'r'
      AND c.relname LIKE p.table_pattern
),
table_columns AS (
    SELECT 
        t.relid,
        t.table_name,
        string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) AS all_cols,
        string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) 
            FILTER (WHERE i.indisprimary) AS pk_cols,
        string_agg(format('%1$I = EXCLUDED.\%1$I', a.attname), ', ' ORDER BY a.attnum) 
            FILTER (WHERE i.indisprimary IS DISTINCT FROM true) AS update_cols
    FROM target_tables t
    JOIN pg_attribute a ON a.attrelid = t.relid
    LEFT JOIN pg_index i ON i.indrelid = t.relid 
                        AND i.indisprimary 
                        AND a.attnum = ANY(i.indkey)
    WHERE a.attnum > 0 
      AND NOT a.attisdropped 
      AND a.attgenerated = ''
    GROUP BY t.relid, t.table_name
)
SELECT 
    CASE p.mode
        -- ① 既存を残す (ignore)
        WHEN 'ignore' THEN
            format(
                'INSERT INTO %I.%I (%s) SELECT %s FROM %I.%I%s;',
                p.dst_schema, tc.table_name, tc.all_cols, tc.all_cols, p.src_schema, tc.table_name,
                CASE WHEN tc.pk_cols IS NOT NULL 
                     THEN format(' ON CONFLICT (%s) DO NOTHING', tc.pk_cols) 
                     ELSE '' END
            )
        -- ② 上書きする (overwrite)
        WHEN 'overwrite' THEN
            format(
                'INSERT INTO %I.%I (%s) SELECT %s FROM %I.%I%s;',
                p.dst_schema, tc.table_name, tc.all_cols, tc.all_cols, p.src_schema, tc.table_name,
                CASE 
                    WHEN tc.pk_cols IS NOT NULL AND tc.update_cols IS NOT NULL 
                        THEN format(' ON CONFLICT (%s) DO UPDATE SET %s', tc.pk_cols, tc.update_cols)
                    WHEN tc.pk_cols IS NOT NULL AND tc.update_cols IS NULL 
                        THEN format(' ON CONFLICT (%s) DO NOTHING', tc.pk_cols)
                    ELSE '' 
                END
            )
        -- ③ Truncateする (truncate)
        WHEN 'truncate' THEN
            format(
                'TRUNCATE TABLE %I.%I CASCADE; INSERT INTO %I.%I (%s) SELECT %s FROM %I.%I;',
                p.dst_schema, tc.table_name, p.dst_schema, tc.table_name, tc.all_cols, tc.all_cols, p.src_schema, tc.table_name
            )
    END AS generated_sql
FROM table_columns tc
CROSS JOIN params p
ORDER BY tc.table_name;
```

---

### 2. 【案1の高速化オプション】インデックス・制約退避 ＆ UNLOGGED化 ＆ 復元SQL生成クエリ
超巨大テーブルへの一括投入時、1行ごとのインデックス更新コストとWAL出力を省いて最速化する手順。

#### ⚠️ 運用上の重要な注意点
1. **必ず「事前準備（DROP）を実行する前」にこのクエリを実行し、生成された事前・事後両方のSQLをファイルへ保存しておくこと**（DROP後に実行しても消えたインデックス定義は取得できない）。
2. **`keep_pk` パラメータの使い分け:**
   * `truncate` モードで移行する場合は **`keep_pk = false`**（PKも含めて全インデックスを剥がし最速投入）。
   * `ignore` / `overwrite` モードで移行する場合は **`keep_pk = true`**（`ON CONFLICT` 句の動作にPK/UNIQUE制約が必須なため、セカンダリインデックスのみを剥がす）。
3. **`SET UNLOGGED` → `SET LOGGED` の特性とレプリケーション注意:**
   * `UNLOGGED` 中にDBプロセスがクラッシュした場合、対象の移行先テーブルのみが自動的に `TRUNCATE` される（移行元には影響しない）。
   * 移行完了後に `SET LOGGED` へ戻す際、**テーブル全件のWAL書き出しが一気に発生し、その間 `AccessExclusiveLock` が維持される**。ストリーミングレプリケーション環境では `SET LOGGED` 時に大量のWALが転送されレプリケーション遅延が発生するため、必ずメンテナンス時間帯に実施すること。
4. **事後復元（インデックス再構築）の高速化:**
   `2_POST_MIGRATION` 実行時は、セッションの先頭で以下を実行するとインデックス作成が劇的に速くなる。
   ```sql
   SET maintenance_work_mem = '2GB';
   SET max_parallel_maintenance_workers = 4;
   ```

```sql
/**
 * 案1の高速データ移行用に、外部キー・主キー・ユニーク制約・インデックスの一時削除とUNLOGGED化（事前準備）、
 * およびLOGGED復帰・各種制約とインデックスの再作成・ANALYZE（事後復元）のSQLを一括生成するクエリ
 *
 * @param dst_schema    移行先スキーマ名 (例: 'db2')
 * @param table_pattern 対象テーブルのLIKE条件 ('%' または 'ese%' など)
 * @param keep_pk       true: 主キーとUNIQUE制約は残す（ignore / overwrite で ON CONFLICT を使う場合）
 *                      false: 主キーも含め全て剥がす（truncate パターンで最速投入する場合）
 * @return phase（実行フェーズ）, step_order（実行順）, ddl_sql（実行すべきDDL文）
 */
WITH params AS (
    SELECT 
        'db2'::text    AS dst_schema,
        'ese%'::text   AS table_pattern,
        false::boolean AS keep_pk -- ★ truncate時は false、ON CONFLICT使用時は true に変更
),
target_tables AS (
    SELECT c.oid AS relid, n.nspname AS schema_name, c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN params p
    WHERE n.nspname = p.dst_schema
      AND c.relkind = 'r'
      AND c.relname LIKE p.table_pattern
),
-- 1. 外部キー制約（対象テーブルが持つFK ＋ 対象テーブルのPKを参照している他テーブルのFK）
fk_constraints AS (
    SELECT DISTINCT
        con.oid AS conid,
        ns.nspname AS table_schema,
        cl.relname AS table_name,
        con.conname AS con_name,
        pg_get_constraintdef(con.oid) AS con_def
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace ns ON ns.oid = cl.relnamespace
    CROSS JOIN params p
    WHERE con.contype = 'f'
      AND (
          con.conrelid IN (SELECT relid FROM target_tables)
          OR (NOT p.keep_pk AND con.confrelid IN (SELECT relid FROM target_tables))
      )
),
-- 2. 主キー（PK）・ユニーク制約（UNIQUE）・排他制約（EXCLUDE）
pk_uq_constraints AS (
    SELECT 
        t.schema_name,
        t.table_name,
        con.conname AS con_name,
        pg_get_constraintdef(con.oid) AS con_def
    FROM target_tables t
    JOIN pg_constraint con ON con.conrelid = t.relid
    CROSS JOIN params p
    WHERE con.contype IN ('p', 'u', 'x')
      AND NOT p.keep_pk
),
-- 3. 通常のセカンダリインデックス（制約に紐づかない純粋なインデックス）
secondary_indexes AS (
    SELECT 
        t.schema_name,
        t.table_name,
        ic.relname AS index_name,
        pg_get_indexdef(i.indexrelid) AS index_def
    FROM target_tables t
    JOIN pg_index i ON i.indrelid = t.relid
    JOIN pg_class ic ON ic.oid = i.indexrelid
    LEFT JOIN pg_constraint con ON con.conindid = i.indexrelid
    WHERE con.oid IS NULL
)
-- 【事前準備 1】外部キー制約の削除
SELECT '1_PRE_MIGRATION' AS phase, 1 AS step_order,
       format('ALTER TABLE %I.%I DROP CONSTRAINT %I;', table_schema, table_name, con_name) AS ddl_sql
FROM fk_constraints
UNION ALL
-- 【事前準備 2】PK・UNIQUE制約の削除（keep_pk = false の場合のみ）
SELECT '1_PRE_MIGRATION', 2,
       format('ALTER TABLE %I.%I DROP CONSTRAINT %I;', schema_name, table_name, con_name)
FROM pk_uq_constraints
UNION ALL
-- 【事前準備 3】セカンダリインデックスの削除
SELECT '1_PRE_MIGRATION', 3,
       format('DROP INDEX %I.%I;', schema_name, index_name)
FROM secondary_indexes
UNION ALL
-- 【事前準備 4】テーブルのUNLOGGED化
SELECT '1_PRE_MIGRATION', 4,
       format('ALTER TABLE %I.%I SET UNLOGGED;', schema_name, table_name)
FROM target_tables
UNION ALL
-- ============================================================================
-- ★ ここでデータ移行（INSERT INTO ... SELECT ...）を実行する ★
-- ============================================================================
-- 【事後復元 1】テーブルのLOGGED復帰
SELECT '2_POST_MIGRATION', 1,
       format('ALTER TABLE %I.%I SET LOGGED;', schema_name, table_name)
FROM target_tables
UNION ALL
-- 【事後復元 2】PK・UNIQUE制約の再作成
SELECT '2_POST_MIGRATION', 2,
       format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s;', schema_name, table_name, con_name, con_def)
FROM pk_uq_constraints
UNION ALL
-- 【事後復元 3】セカンダリインデックスの再作成
SELECT '2_POST_MIGRATION', 3,
       index_def || ';'
FROM secondary_indexes
UNION ALL
-- 【事後復元 4】外部キー制約の再作成
SELECT '2_POST_MIGRATION', 4,
       format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s;', table_schema, table_name, con_name, con_def)
FROM fk_constraints
UNION ALL
-- 【事後復元 5】統計情報の更新（ANALYZE）
SELECT '2_POST_MIGRATION', 5,
       format('ANALYZE %I.%I;', schema_name, table_name)
FROM target_tables
ORDER BY phase, step_order, ddl_sql;
```

---

### 3. 【案2】別サーバー間（`psql \copy` バイナリパイプライン）の自動コマンド生成クエリ
サーバーを跨ぐ移行において、一時ファイルを作らずネットワーク越しにバイナリストリームを直結させる最速手法。
`COPY` コマンド自体には `ON CONFLICT` がないため、`ignore` / `overwrite` 時は移行先のメモリ上の一時テーブル（`TEMP TABLE` ＝ 自動的にUNLOGGEDかつインデックスなし）で受けてから本テーブルへマージする。`truncate` 時は一時テーブルを介さず本テーブルへ直接流し込む。

```sql
/**
 * 案2: 別サーバーへ psql \copy (FORMAT binary) パイプラインで高速移行するBashワンライナー生成クエリ
 * 
 * @param src_conn      移行元サーバーのpsql接続文字列
 * @param dst_conn      移行先サーバーのpsql接続文字列
 * @param src_schema    移行元スキーマ名
 * @param dst_schema    移行先スキーマ名
 * @param table_pattern 対象テーブルのLIKE条件 ('%' または 'ese%' など)
 * @param mode          競合時の挙動 ('ignore': 既存を残す, 'overwrite': 上書きする, 'truncate': 事前に空にする)
 * @return Bashターミナルでそのまま実行可能なパイプラインコマンド文字列
 */
WITH params AS (
    SELECT 
        'psql -h src_host -p 5432 -U postgres -d mydb'::text AS src_conn,
        'psql -h dst_host -p 5432 -U postgres -d mydb'::text AS dst_conn,
        'db1'::text       AS src_schema,
        'db2'::text       AS dst_schema,
        'ese%'::text      AS table_pattern, -- 全テーブルなら '%' に変更
        'overwrite'::text AS mode           -- 'ignore' | 'overwrite' | 'truncate'
),
target_tables AS (
    SELECT 
        c.oid AS relid,
        c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN params p
    WHERE n.nspname = p.src_schema
      AND c.relkind = 'r'
      AND c.relname LIKE p.table_pattern
),
table_columns AS (
    SELECT 
        t.relid,
        t.table_name,
        string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) AS all_cols,
        string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) 
            FILTER (WHERE i.indisprimary) AS pk_cols,
        string_agg(format('%1$I = EXCLUDED.\%1$I', a.attname), ', ' ORDER BY a.attnum) 
            FILTER (WHERE i.indisprimary IS DISTINCT FROM true) AS update_cols
    FROM target_tables t
    JOIN pg_attribute a ON a.attrelid = t.relid
    LEFT JOIN pg_index i ON i.indrelid = t.relid 
                        AND i.indisprimary 
                        AND a.attnum = ANY(i.indkey)
    WHERE a.attnum > 0 
      AND NOT a.attisdropped 
      AND a.attgenerated = ''
    GROUP BY t.relid, t.table_name
)
SELECT 
    CASE p.mode
        -- ① 既存を残す (ignore): 一時テーブルで受けて ON CONFLICT DO NOTHING
        WHEN 'ignore' THEN
            format(
                '%s -c "\copy %I.%I (%s) TO STDOUT (FORMAT binary)" | %s -c "CREATE TEMP TABLE tmp_import (LIKE %I.%I); COPY tmp_import (%s) FROM STDIN (FORMAT binary); INSERT INTO %I.%I (%s) SELECT %s FROM tmp_import%s;"',
                p.src_conn, p.src_schema, tc.table_name, tc.all_cols,
                p.dst_conn, p.dst_schema, tc.table_name, tc.all_cols,
                p.dst_schema, tc.table_name, tc.all_cols, tc.all_cols,
                CASE WHEN tc.pk_cols IS NOT NULL 
                     THEN format(' ON CONFLICT (%s) DO NOTHING', tc.pk_cols) 
                     ELSE '' END
            )
        -- ② 上書きする (overwrite): 一時テーブルで受けて ON CONFLICT DO UPDATE
        WHEN 'overwrite' THEN
            format(
                '%s -c "\copy %I.%I (%s) TO STDOUT (FORMAT binary)" | %s -c "CREATE TEMP TABLE tmp_import (LIKE %I.%I); COPY tmp_import (%s) FROM STDIN (FORMAT binary); INSERT INTO %I.%I (%s) SELECT %s FROM tmp_import%s;"',
                p.src_conn, p.src_schema, tc.table_name, tc.all_cols,
                p.dst_conn, p.dst_schema, tc.table_name, tc.all_cols,
                p.dst_schema, tc.table_name, tc.all_cols, tc.all_cols,
                CASE 
                    WHEN tc.pk_cols IS NOT NULL AND tc.update_cols IS NOT NULL 
                        THEN format(' ON CONFLICT (%s) DO UPDATE SET %s', tc.pk_cols, tc.update_cols)
                    WHEN tc.pk_cols IS NOT NULL AND tc.update_cols IS NULL 
                        THEN format(' ON CONFLICT (%s) DO NOTHING', tc.pk_cols)
                    ELSE '' 
                END
            )
        -- ③ Truncateする (truncate): 一時テーブル不要！TRUNCATE直後に直接バイナリCOPYで最速投入
        WHEN 'truncate' THEN
            format(
                '%s -c "\copy %I.%I (%s) TO STDOUT (FORMAT binary)" | %s -c "TRUNCATE TABLE %I.%I CASCADE; COPY %I.%I (%s) FROM STDIN (FORMAT binary);"',
                p.src_conn, p.src_schema, tc.table_name, tc.all_cols,
                p.dst_conn, p.dst_schema, tc.table_name, p.dst_schema, tc.table_name, tc.all_cols
            )
    END AS generated_bash_cmd
FROM table_columns tc
CROSS JOIN params p
ORDER BY tc.table_name;
```

---

### 4. 【移行後の必須処理】シーケンス（採番値）を最大IDへ一括同期するSQL生成クエリ
データを直接 `INSERT` / `COPY` すると、`SERIAL` や `IDENTITY` カラムに紐づくシーケンスの現在値が更新されないため、移行後に新規登録を行うと主キー重複エラーが発生する。以下のクエリで生成した `setval` 文を実行し、現在のテーブル内の最大値（`MAX`）に一括同期すること。

```sql
/**
 * 対象スキーマ内の全テーブルのシーケンス（SERIAL / IDENTITY）を
 * 現在のテーブル内の最大値（MAX）に一括同期するSQLの自動生成クエリ
 *
 * @param dst_schema    調整対象のスキーマ名 (例: 'db2')
 * @param table_pattern 対象テーブルのLIKE条件 ('%' で全テーブル, 'ese%' で特定テーブル)
 * @return 各シーケンスを最大値に更新する SELECT setval(...) 文のリスト
 */
WITH params AS (
    SELECT 
        'db2'::text  AS dst_schema,
        'ese%'::text AS table_pattern -- 全テーブルなら '%' に変更
)
SELECT 
    format(
        -- テーブルが空(MAXがNULL)の場合は初期値1に戻し次回1から採番(false)、データがある場合はMAX値にセットし次回MAX+1から採番(true)
        'SELECT setval(%L, COALESCE((SELECT MAX(%I) FROM %I.%I), 1), (SELECT MAX(%I) IS NOT NULL FROM %I.%I));',
        pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname),
        a.attname, n.nspname, c.relname,
        a.attname, n.nspname, c.relname
    ) AS adjust_sequence_sql
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
CROSS JOIN params p
WHERE n.nspname = p.dst_schema
  AND c.relkind = 'r'
  AND c.relname LIKE p.table_pattern
  AND a.attnum > 0 
  AND NOT a.attisdropped
  AND pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname) IS NOT NULL
ORDER BY c.relname, a.attnum;
```
