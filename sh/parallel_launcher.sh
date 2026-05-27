#!/bin/bash

# --- 引数のバリデーション ---
if [ $# -lt 2 ]; then
    echo "【エラー】引数が不足しています。"
    echo "使い方: $0 <実行するシェルスクリプト> <並列数>"
    echo "例: $0 main_shell.sh 5"
    exit 1
fi

TARGET_SHELL=$1
PARALLEL_COUNT=$2

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# 起動したプロセスの管理用
PIDS=()
declare -A PID_TO_SEQ  # ★PIDをキーにして、並列番号（引数）を保持する連想配列

echo "========================================="
echo "[主処理] 非同期の並列実行を開始します。"
echo "対象シェル: $TARGET_SHELL"
echo "総並列数  : $PARALLEL_COUNT"
echo "========================================="

# [1] 非同期での一斉起動処理
for ((i=1; i<=${PARALLEL_COUNT}; i++)); do
    SHELL_BASE=$(basename "$TARGET_SHELL" .sh)
    LOG_FILE="$LOG_DIR/${SHELL_BASE}_seq${i}.log"
    
    echo "[起動開始] $TARGET_SHELL を実行中... (並列番号: $i -> Log: $LOG_FILE)"
    
    # 対象のシェルに「並列番号(i)」を第1引数として渡して非同期実行
    bash "$TARGET_SHELL" "$i" > "$LOG_FILE" 2>&1 &
    
    CURRENT_PID=$!
    PIDS+=($CURRENT_PID)
    PID_TO_SEQ[$CURRENT_PID]=$i  # ★PIDと引数（並列番号）をマッピング
done

echo "========================================="
echo "すべてのプロセスの起動コマンドを投げました。"
echo "全処理が完了するまで待機します..."
echo "========================================="

# 異常終了した引数（並列番号）を格納する配列
FAILED_SEQS=()

# [2] すべてのPIDの完了を同期待機
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        # ★エラー（戻り値が0以外）だった場合、連想配列から対応する引数を取得して保存
        FAILED_SEQS+=("${PID_TO_SEQ[$pid]}")
    fi
done

echo "========================================="
# [3] 結果の判定と出力
if [ ${#FAILED_SEQS[@]} -gt 0 ]; then
    # 配列の中身を「、」で連結する処理
    IFS="、"
    FAILED_STR="${FAILED_SEQS[*]}"
    unset IFS
    
    # ご要望の形式でエラーメッセージを出力
    echo "【エラー】引数=${FAILED_STR} の $(basename "$TARGET_SHELL") がエラー終了しました。"
    echo "詳細は $LOG_DIR/ 内の各ログファイルを確認してください。"
    echo "========================================="
    exit 1
else
    echo "[完了] すべての非同期シェルが正常に終了しました。"
    echo "========================================="
    exit 0
fi
