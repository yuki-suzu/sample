そうよ！その通りだわ！
`window.__APP_ENV__` を読み込む専用のサービスを1つ作って、そこからヘッダーやフッターに反映させるのが一番スマートよ！

TypeScriptで型安全に扱いながら、ヘッダー・フッターの色を切り替える具体的な手順を教えてあげるわね！

---

### ステップ1：`window.__APP_ENV__` の型を定義してサービス化する

まずはブラウザの `window` オブジェクトに勝手に生やした変数を、TypeScriptに「こういう型だよ」と教えてあげるの。

```typescript
// src/app/core/config/env.service.ts
import { Injectable } from '@angular/core';

// 設定オブジェクトの型
export interface AppEnv {
  isTest: boolean;
  envName: string;
}

// windowオブジェクトに __APP_ENV__ を拡張
declare global {
  interface Window {
    __APP_ENV__?: AppEnv;
  }
}

@Injectable({
  providedIn: 'root',
})
export class EnvService {
  // 万が一ファイルが無かった時（ローカル開発時など）のデフォルト値を用意
  private readonly config: AppEnv = window.__APP_ENV__ ?? {
    isTest: false,
    envName: 'prod',
  };

  /** テスト環境かどうか */
  get isTest(): boolean {
    return this.config.isTest;
  }

  /** 環境名（'test' や 'prod'） */
  get envName(): string {
    return this.config.envName;
  }
}

```

---

### ステップ2：ヘッダーやフッターの色を切り替える

色の切り替え方にはいくつかあるけれど、「CSSクラスで切り替える」のが一番スッキリして保守しやすいわ！

#### パターンA：コンポーネントに直接クラスを当てる場合

ヘッダーコンポーネントで `EnvService` を注入して、テンプレートでクラスをバインドするの。

```typescript
// src/app/layout/header/header.component.ts (Angular 17 Standalone)
import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EnvService } from '../../core/config/env.service';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [CommonModule],
  template: `
    <!-- isTestがtrueの時だけ 'test-theme' クラスを付与 -->
    <header class="app-header" [class.test-theme]="isTest">
      <div class="logo">社内システム</div>
      <div *ngIf="isTest" class="env-badge">【総合テスト環境】</div>
    </header>
  `,
  styleUrl: './header.component.scss',
})
export class HeaderComponent {
  private envService = inject(EnvService);
  readonly isTest = this.envService.isTest;
}

```

```scss
// header.component.scss
.app-header {
  height: 60px;
  display: flex;
  align-items: center;
  padding: 0 16px;
  background-color: #1976d2; // 本番環境のデフォルト色（例：ブルー）
  color: #ffffff;

  // テスト環境用のスタイル
  &.test-theme {
    background-color: #d32f2f; // テスト環境の色（注意を促すレッドやオレンジなど）
  }

  .env-badge {
    margin-left: 12px;
    font-weight: bold;
    background-color: #fff;
    color: #d32f2f;
    padding: 2px 8px;
    border-radius: 4px;
  }
}

```

※フッターも全く同じように `[class.test-theme]="isTest"` を付けてあげればOKよ！

---

#### パターンB：アプリ全体（body）に環境クラスを付けて一括制御する（おすすめ！）

「ヘッダーもフッターも、ついでにボタンや帯もテスト環境カラーにしたい！」という場合は、`AppComponent` 起動時に `<body>` へクラスを1つ付けておくのがとても綺麗よ。

```typescript
// src/app/app.component.ts
import { Component, inject, OnInit } from '@angular/core';
import { EnvService } from './core/config/env.service';

@Component({
  selector: 'app-root',
  standalone: true,
  templateUrl: './app.component.html',
})
export class AppComponent implements OnInit {
  private envService = inject(EnvService);

  ngOnInit(): void {
    if (this.envService.isTest) {
      // <body> に 'env-test' クラスを付与
      document.body.classList.add('env-test');
    }
  }
}

```

グローバルCSS（`styles.scss`）やCSS変数を使っておけば、ヘッダーもフッターも個別のTypeScriptで判定を書く必要すらなくなるわ！

```scss
// src/styles.scss
:root {
  --header-bg: #1976d2; // 本番色
  --footer-bg: #424242;
}

// bodyに 'env-test' が付いている時はテーマ色を丸ごと上書き
body.env-test {
  --header-bg: #e65100; // テスト環境（鮮やかなオレンジ等）
  --footer-bg: #bf360c;
}

// ヘッダーやフッターのSCSSでは変数を使うだけ！
.app-header {
  background-color: var(--header-bg);
}
.app-footer {
  background-color: var(--footer-bg);
}

```

---

### まとめ

1. `index.html` で読み込んだ `window.__APP_ENV__` を `EnvService` で受け取る。
2. あとは `isTest` フラグを見て、CSSクラスやCSS変数を切り替える。

これなら非同期処理もゼロだから、画面が表示された瞬間からパッとテスト環境の色になって、チラつき（FOUC）も起きないわよ！安心して実装してみてちょうだい！
