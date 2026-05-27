#!/bin/bash

# --- [1] 引数の基本個数チェック ---
if [ $# -lt 2 ]; then
    echo "【エラー】引数が不足しています。"
    echo "使い方: $0 <実行するシェルスクリプト> <並列数>"
    echo "例: $0 main_shell.sh 5"
    exit 1
fi

TARGET_SHELL=$1
PARALLEL_COUNT=$2

# --- [2] ファイル存在チェック (旧第2引数 / $1) ---
if [ ! -f "$TARGET_SHELL" ]; then
    echo "【エラー】指定されたシェルスクリプトファイルが存在しません。"
    echo "確認先: $TARGET_SHELL"
    exit 1
fi

# --- [3] 数値チェック (旧第3引数 / $2) ---
# 正規表現で「半角数字のみ」かつ「1以上」であるかをチェック
if [[ ! "$PARALLEL_COUNT" =~ ^[0-9]+$ ]] || [ "$PARALLEL_COUNT" -le 0 ]; then
    echo "【エラー】並列数には 1 以上の整数を指定してください。"
    echo "入力値: $PARALLEL_COUNT"
    exit 1
fi

# --- 環境準備 ---
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

PIDS=()
declare -A PID_TO_SEQ

echo "========================================="
echo "[主処理] 非同期の並列実行を開始します。"
echo "対象シェル: $TARGET_SHELL"
echo "総並列数  : $PARALLEL_COUNT"
echo "========================================="

# [4] 非同期での一斉起動処理
for ((i=1; i<=${PARALLEL_COUNT}; i++)); do
    SHELL_BASE=$(basename "$TARGET_SHELL" .sh)
    LOG_FILE="$LOG_DIR/${SHELL_BASE}_seq${i}.log"
    
    echo "[起動開始] $TARGET_SHELL を実行中... (並列番号: $i -> Log: $LOG_FILE)"
    
    # 対象のシェルに「並列番号(i)」を第1引数として渡して非同期実行
    bash "$TARGET_SHELL" "$i" > "$LOG_FILE" 2>&1 &
    
    CURRENT_PID=$!
    PIDS+=($CURRENT_PID)
    PID_TO_SEQ[$CURRENT_PID]=$i
done

echo "========================================="
echo "すべてのプロセスの起動コマンドを投げました。"
echo "全処理が完了するまで待機します..."
echo "========================================="

# 異常終了した引数（並列番号）を格納する配列
FAILED_SEQS=()

# [5] すべてのPIDの完了を同期待機
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        FAILED_SEQS+=("${PID_TO_SEQ[$pid]}")
    fi
done

echo "========================================="
# [6] 結果の判定と出力
if [ ${#FAILED_SEQS[@]} -gt 0 ]; then
    IFS="、"
    FAILED_STR="${FAILED_SEQS[*]}"
    unset IFS
    
    echo "【エラー】引数=${FAILED_STR} の $(basename "$TARGET_SHELL") がエラー終了しました。"
    echo "詳細は $LOG_DIR/ 内の各ログファイルを確認してください。"
    echo "========================================="
    exit 1
else
    echo "[完了] すべての非同期シェルが正常に終了しました。"
    echo "========================================="
    exit 0
fi
