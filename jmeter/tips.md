### build.gradle
`testImplementation 'us.abstracta.jmeter:jmeter-java-dsl:1.29'`

### IntelliJの Terminal タブを開き、以下のコマンドを1行叩く
`jbang us.abstracta.jmeter:jmeter-java-dsl-cli jmx2dsl your-scenario.jmx > src/test/java/MyPerformanceTest.java`


### シェル作成
dos
```sh
# Windowsのフォルダへ移動（Git Bashでのパス表現の例）
cd /c/JMeter/projects/scenarios

# Linux用のスクリプトをWindows上で事前生成
for f in *.jmx; do
  echo "jmeter -n -t \"./$f\" -l \"./${f%.jmx}.jtl\" -Jthreads=2 -Jrampup=4 -Jloops=3 && jmeter -g \"./${f%.jmx}.jtl\" -o \"./${f%.jmx}_report\""
done > run_jmeter.sh
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
