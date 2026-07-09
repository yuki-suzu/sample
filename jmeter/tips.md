### build.gradle
`testImplementation 'us.abstracta.jmeter:jmeter-java-dsl:1.29'`

### IntelliJの Terminal タブを開き、以下のコマンドを1行叩く
`jbang jmx2dsl@abstracta your-scenario.jmx > src/test/java/MyPerformanceTest.java`
