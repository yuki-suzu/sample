package com.example.demo.service;

import com.example.demo.dto.UserDto;
import com.opencsv.CSVWriterBuilder;
import com.opencsv.ICSVWriter;
import org.postgresql.copy.CopyManager;
import org.postgresql.core.BaseConnection;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.PipedReader;
import java.io.PipedWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * OpenCSVライブラリとPostgreSQLのCopyManager機能を組み合わせ、JavaのListデータから
 * 大量のレコードを安全かつ高速に一括登録（バルクインサート）するためのサービスコンポーネントです。
 * <p>
 * 文字列のエスケープ処理（改行やクォートの考慮）をOpenCSVに委譲することで、コードの堅牢性を高めつつ、
 * Java 21の仮想スレッド（Virtual Threads）とパイプストリームによる省メモリなストリーミング転送を実現しています。
 * </p>
 */
@Service
public class BulkInsertWithOpenCsvService {

    private final DataSource dataSource;
    
    /** PostgreSQLが確実に解釈できる日時フォーマットの定義 */
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * BulkInsertWithOpenCsvServiceのインスタンスを構築します。
     *
     * @param dataSource Springが管理するデータソース。トランザクション同期に使用されます。
     */
    public BulkInsertWithOpenCsvService(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * 指定されたユーザーデータのリストを、OpenCSVでCSVフォーマットに変換しながら、
     * PostgreSQLのCOPYコマンドを用いて一括でデータベースに挿入します。
     * <p>
     * このメソッドはSpringの@Transactionalアノテーション配下で動作し、既存のデータベーストランザクションに参加します。
     * データ内に改行やカンマが含まれていても、OpenCSVが自動的に適切なクォーティング（RFC 4180準拠）を行うため安全です。
     * </p>
     *
     * @param userList 挿入対象のユーザーデータを含むオブジェクトのリスト。
     * リストが空、またはnullの場合は何も処理を行いません。
     * @throws SQLException データベースアクセスまたはCOPYコマンドの実行中にエラーが発生した場合
     * @throws IOException  パイプストリームを介したデータの読み書き中にエラーが発生した場合
     */
    @Transactional
    public void copyInsertUsersWithOpenCsv(List<UserDto> userList) throws SQLException, IOException {
        if (userList == null || userList.isEmpty()) {
            return;
        }

        // Springのトランザクション管理下にある現在のConnectionを取得
        Connection conn = DataSourceUtils.getConnection(dataSource);

        try {
            // PostgreSQL固有のConnectionインターフェースにアンラップ
            BaseConnection pgConn = conn.unwrap(BaseConnection.class);
            CopyManager copyManager = new CopyManager(pgConn);

            // COPYコマンド（CSVフォーマットを指定。エスケープ文字もダブルクォーテーションに統一）
            String copySql = "COPY target_table (id, name, email, created_at) FROM STDIN WITH (FORMAT csv, HEADER false, QUOTE '\"', ESCAPE '\"', NULL '')";

            // メモリを節約するため、PipedReaderとPipedWriterを接続
            try (PipedWriter writer = new PipedWriter();
                 PipedReader reader = new PipedReader(writer)) {

                // Java 21の仮想スレッドを使用して、非同期書き込みタスクを実行
                try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {

                    executor.submit(() -> {
                        // OpenCSVのCSVWriterBuilderを使って、PostgreSQLのCSV設定と完全同期させる
                        try (ICSVWriter csvWriter = new CSVWriterBuilder(writer)
                                .withSeparator(',')     // 区切り文字
                                .withQuoteChar('"')     // 囲み文字
                                .withEscapeChar('"')    // エスケープ文字（PostgreSQLのESCAPE '"' と合わせる）
                                .build()) {

                            for (UserDto user : userList) {
                                // 各フィールドをString配列にマッピング（null安全を考慮）
                                String[] row = new String[]{
                                        user.id() != null ? user.id().toString() : "",
                                        user.name() != null ? user.name() : "",
                                        user.email() != null ? user.email() : "",
                                        user.createdAt() != null ? user.createdAt().format(DATE_TIME_FORMATTER) : ""
                                };
                                // OpenCSVが自動でエスケープやクォートを行い、パイプストリームへ順次書き込む
                                csvWriter.writeNext(row);
                            }
                        } catch (IOException e) {
                            throw new RuntimeException("OpenCSVを介したパイプストリームへの書き込み中に例外が発生しました。", e);
                        }
                    });

                    // メインスレッド：パイプから流れてくるCSVデータをCopyManagerがリアルタイムにDBへ吸い上げる
                    copyManager.copyIn(copySql, reader);
                }
            }
        } finally {
            // Connectionを適切にリリース（トランザクションのコミット/ロールバックはSpringが制御）
            DataSourceUtils.releaseConnection(conn, dataSource);
        }
    }
}
