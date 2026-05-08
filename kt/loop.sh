#!/bin/bash
set -e

BASE_TMP_DIR=$(mktemp -d /tmp/scan_base_XXXXXX)
trap "rm -rf '$BASE_TMP_DIR'" EXIT

LIST_FILE="zip_list.txt"

# ==========================================
# 前半戦：すべてのZIPをひたすら解凍・分割する
# ==========================================
while IFS= read -r ZIP_PATH; do
    if [ -z "$ZIP_PATH" ] || [ ! -f "$ZIP_PATH" ]; then
        continue
    fi
    
    # ZIPのファイル名だけを抽出 (例: data.zip)
    ZIP_NAME=$(basename "$ZIP_PATH")
    
    # 親ディレクトリの中に、ZIPごとの専用サブディレクトリを作る
    # 例: /tmp/scan_base_12345/data.zip/
    SUB_TMP_DIR="$BASE_TMP_DIR/$ZIP_NAME"
    mkdir -p "$SUB_TMP_DIR"
    
    echo "解凍中: $ZIP_PATH"
    unzip -p "$ZIP_PATH" | split -b 1500m - "$SUB_TMP_DIR/chunk_"

done < "$LIST_FILE"

# ==========================================
# 後半戦：ループの外で「一撃」でスキャンする
# ==========================================
echo "全ファイルの解凍完了。一括スキャンを開始します..."

SCAN_RESULT=0
# -r (サブディレクトリもスキャン) と -i (ウイルス検知時のみログ出力) を追加
nice -n 19 ionice -c 3 clamscan \
  -r -i \
  --max-filesize=2000M \
  --max-scansize=2000M \
  --scan-archive=no \
  "$BASE_TMP_DIR/" || SCAN_RESULT=$?

# ==========================================
# 結果の判定
# ==========================================
if [ $SCAN_RESULT -eq 0 ]; then
    echo "[OK] すべてのファイルは安全です。"
elif [ $SCAN_RESULT -eq 1 ]; then
    # -i を付けているため、標準出力に「どのZIPのどのchunkから出たか」が綺麗に残ります
    echo "[NG] ウイルスを検知しました！ログを確認してください。"
else
    echo "[ERROR] スキャン中にエラーが発生しました(コード:$SCAN_RESULT)。"
fi
