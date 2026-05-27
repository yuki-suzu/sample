#!/bin/bash

# --- 引数のバリデーション ---
if [ $# -lt 2 ]; then
    echo "【エラー】引数が不足しています。"
    echo "使い方: $0 <実行するシェルスクリプト> <並列数>"
    echo "例: $0 child_process.sh 5"
    exit 1
fi

# 引数を変数に格納
TARGET_SHELL=$1
PARALLEL_COUNT=$2

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# 起動したプロセスのPID（プロセスID）を記録する配列
PIDS=()

echo "========================================="
echo "[主処理] 非同期の並列実行を開始します。"
echo "対象シェル: $TARGET_SHELL"
echo "総並列数  : $PARALLEL_COUNT"
echo "========================================="

# [1] 引数で指定された並列数分、非同期で一斉起動
for ((i=1; i<=${PARALLEL_COUNT}; i++)); do
    # ログファイル名に並列番号を付与（例: child_process_seq1.log）
    SHELL_BASE=$(basename "$TARGET_SHELL" .sh)
    LOG_FILE="$LOG_DIR/${SHELL_BASE}_seq${i}.log"
    
    echo "[起動開始] $TARGET_SHELL を実行中... (並列番号: $i -> Log: $LOG_FILE)"
    
    # 対象のシェルに「並列番号(i)」を第1引数として渡して非同期実行 (&)
    # stdoutとstderrを個別のログファイルにリダイレクト
    bash "$TARGET_SHELL" "$i" > "$LOG_FILE" 2>&1 &
    
    # 直前にバックグラウンド実行したプロセスのPIDを取得して保持
    PIDS+=($!)
done

echo "========================================="
echo "すべてのプロセスの起動コマンドを投げました。"
echo "全処理が完了するまで待機します（Ctrl+C でスクリプトを抜けても裏のプロセスは動きます）。"
echo "進捗の確認: tail -f $LOG_DIR/*.log"
echo "========================================="

# [2] 保持したすべてのPIDの完了を同期待機
# これにより、すべての子プロセスが完了するまで本シェルは終了しません
wait "${PIDS[@]}"

echo "========================================="
echo "[完了] すべての非同期シェルが終了しました。本シェルを終了します。"
echo "========================================="
