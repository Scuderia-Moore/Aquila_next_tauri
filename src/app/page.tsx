"use client";
import { DiscordOAuthButton } from "@/components/DiscordOAuthButton";

export default function Home() {
  return (
    <main className="min-h-screen p-8 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <h1 className="text-xl font-semibold">Discord ログイン動作確認</h1>
        <DiscordOAuthButton />
        <p className="text-sm text-gray-500">ボタンを押してブラウザでログインしてください。</p>
      </div>
    </main>
  );
}
