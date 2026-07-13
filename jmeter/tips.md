### build.gradle
`testImplementation 'us.abstracta.jmeter:jmeter-java-dsl:1.29'`

### IntelliJの Terminal タブを開き、以下のコマンドを1行叩く
`jbang us.abstracta.jmeter:jmeter-java-dsl-cli jmx2dsl your-scenario.jmx > src/test/java/MyPerformanceTest.java`


### シェル作成
bash
```sh
# 1. スクリプトファイルを初期化
echo '#!/bin/bash' > run_jmeter.sh
echo '# --- 1. 負荷テストを一斉に並列実行 ---' >> run_jmeter.sh

# 2. 引数に「-Jthroughput」「-Jperiod」「-Jduration」を完全配備して書き出し
for f in *.jmx; do
  echo "jmeter -n -t \"./$f\" -l \"./${f%.jmx}.jtl\" -Jthreads=10 -Jrampup=3 -Jloops=-1 -Jduration=600 -Jthroughput=100 -Jperiod=1 &" >> run_jmeter.sh
done

# 3. 同時実行のストッパー
echo 'wait' >> run_jmeter.sh
echo '' >> run_jmeter.sh
echo '# --- 2. テスト完了後にレポートをまとめて生成 ---' >> run_jmeter.sh

# 4. レポート生成部分
for f in *.jmx; do
  echo "jmeter -g \"./${f%.jmx}.jtl\" -o \"./${f%.jmx}_report\"" >> run_jmeter.sh
done
```

#### 実行
```sh
# 1. スクリプトに実行権限を与える
chmod +x run_jmeter.sh

# 2. nohupでバックグラウンド実行（完全非同期）
nohup ./run_jmeter.sh > jmeter_dock.log 2>&1 &

### 以降は実行後に随時実施
# 3. 実行状況監視
tail -f jmeter_dock.log

# 4. 実行中プロセス確認
ps aux | grep jmeter

# 5. 途中で緊急停止
pkill -f jmeter
```
