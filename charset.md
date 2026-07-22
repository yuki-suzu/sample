| 16進数コード | 略称 | 正式名称（英語 / 日本語） | 主な役割・実務での正体 |
| :--- | :--- | :--- | :--- |
| **`0x00`** | **NUL** | Null / 空文字 | **【最凶】** 文字列の終端を表す（ヌル文字） |
| `0x01` | SOH | Start of Heading / ヘッダ開始 | 通信データのヘッダの始まりを示す |
| `0x02` | STX | Start of Text / テキスト開始 | 本文（テキスト）の始まりを示す |
| `0x03` | ETX | End of Text / テキスト終了 | 本文（テキスト）の終わりを示す |
| `0x04` | EOT | End of Transmission / 転送終了 | データ通信全体の終了を示す |
| `0x05` | ENQ | Enquiry / 問合せ | 相手の端末に応答を求める（対話用） |
| `0x06` | ACK | Acknowledge / 肯定応答 | 「データ正しく届いたよ」という返事 |
| `0x07` | BEL | Bell / ベル | 端末のビープ音（ブザー）を鳴らす |
| `0x08` | BS | Backspace / 後退 | カーソルを1文字戻す（バックスペース） |
| **`0x09`** | **HT** | Horizontal Tabulation / 水平タブ | **【注意】** キーボードの「Tab」キーの入力 |
| **`0x0A`** | **LF** | Line Feed / 改行 | **【注意】** UNIX/Linux系やJavaの標準改行 |
| `0x0B` | VT | Vertical Tabulation / 垂直タブ | 縦方向のタブ（現代ではほぼ絶滅） |
| `0x0C` | FF | Form Feed / 改ページ | 印刷時に次のページへ送る |
| **`0x0D`** | **CR** | Carriage Return / 復帰 | **【注意】** Windowsの改行（CR+LF）の片割れ |
| `0x0E` | SO | Shift Out / シフトアウト | 別の文字集合へ切り替えるスイッチ |
| `0x0F` | SI | Shift In / シフトイン | 元の文字集合へ戻るスイッチ |
| `0x10` | DLE | Data Link Escape / 伝送制御拡張 | 制御文字自体をデータとして扱うためのエスケープ |
| `0x11` | DC1 | Device Control 1 / 装置制御1 | 端末機器の制御（通信の再開など） |
| `0x12` | DC2 | Device Control 2 / 装置制御2 | 端末機器の制御 |
| `0x13` | DC3 | Device Control 3 / 装置制御3 | 端末機器の制御（通信の一時停止など） |
| `0x14` | DC4 | Device Control 4 / 装置制御4 | 端末機器の制御 |
| `0x15` | NAK | Negative Acknowledge / 否定応答 | 「データが壊れてるよ」というエラー返事 |
| `0x16` | SYN | Synchronous Idle / 同期信号 | 通信の同期をとるためのダミーデータ |
| `0x17` | ETB | End of Transmission Block / ブロック終了 | 分割されたデータブロックの終わりを示す |
| `0x18` | CAN | Cancel / 取消 | 直前のデータを無効にして取り消す |
| `0x19` | EM | End of Medium / 媒体終端 | カートリッジやテープなどの物理的な終わりの検知 |
| `0x1A` | SUB | Substitute / 置換 | エラー文字の代わりに置き換える文字 |
| **`0x1B`** | **ESC** | Escape / 拡張 | **【注意】** キーボードの「Esc」キー。拡張コマンド用 |
| `0x1C` | FS | File Separator / ファイル分離 | データの区切り（大：ファイルの境目） |
| `0x1D` | GS | Group Separator / グループ分離 | データの区切り（中：グループの境目） |
| `0x1E` | RS | Record Separator / レコード分離 | データの区切り（小：レコードの境目） |
| `0x1F` | US | Unit Separator / ユニット分離 | データの区切り（最小：項目の境目） |
| **`0x7F`** | **DEL** | **Delete / 抹消（消去）** | **【注意】** 独立した特殊制御文字。Deleteキー相当 |

```java
import java.util.regex.Pattern;

public class JisValidationUtils {

    // 【解説】
    // \p{Cc} : JIS X 0211の制御文字（0x00〜0x1F, 0x7F）すべてを対象とする
    // &&[^\r\n] : その中から、CR(\r) と LF(\n) だけを「除外」する
    // つまり：改行以外の制御文字（NUL, タブ, ESC, DELなど）が1文字でもあればマッチする
    private static final Pattern INVALID_CONTROL_CHARS = Pattern.compile(".*[\\p{Cc}&&[^\\r\\n]].*");

    public static boolean isValidInput(String input) {
        if (input == null || input.isEmpty()) {
            return true;
        }

        // 1段目：改行以外の有害な制御文字（31文字）が含まれていたら即アウト（False）
        if (INVALID_CONTROL_CHARS.matcher(input).matches()) {
            return false;
        }

        // 2段目：いつもの厳格なJIS X 0213文字コードチェック（改行や半角カナはここを通る）
        // ※あらかじめ用意してあるCharsetEncoderを使用
        return encoder.canEncode(input);
    }
}
```


**Shift_JIS-2004**とは、JIS X 0213:2004（7ビット及び8ビットの2バイト情報交換用符号化漢字集合）の附属書1において定義されている符号化方式（エンコーディング）です。

従来のShift_JISとの下位互換性を維持しながら、JIS X 0213で拡張された文字群に対応するため、1バイト領域と2バイト領域に以下の文字集合を含んでいます。

---

### 構成に含まれる文字集合

#### 1. 1バイト領域

* **JIS X 0211（C0制御文字集合およびDEL）**
* 改行（CR / LF）、タブ（HT）、ヌル文字（NUL）などのシステム制御コード（全33文字）。


* **JIS X 0201（ラテン文字および半角片仮名）**
* 半角英数字および半角記号（`0x20` 〜 `0x7E`）。
* 半角カタカナおよび記号（`0xA1` 〜 `0xDF`）。



#### 2. 2バイト領域

* **JIS X 0213（非漢字および第1〜第4水準漢字）**
* **非漢字**: ひらがな、全角カタカナ、全角英数字、各種記号、単位記号、丸数字など。
* **漢字（計10,055文字）**:
* 第1水準漢字（2,965文字）
* 第2水準漢字（3,390文字）
* 第3水準漢字（1,259文字）
* 第4水準漢字（2,441文字）





---

### 概要

Shift_JIS-2004は、過去のシステム互換性を維持する目的で**JIS X 0201（半角カタカナを含む）およびJIS X 0211（制御文字）を1バイト領域に内包**し、2バイト領域に**JIS X 0213（第1〜第4水準漢字および全角記号群）を割り当てた符号化構造**となっています。












