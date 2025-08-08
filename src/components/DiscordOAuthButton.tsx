"use client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useEffect, useState } from "react";

export function DiscordOAuthButton() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);

  useEffect(() => {
    // 認証成功イベント
    const unlistenDone = listen("oauth:done", (event: any) => {
      console.log("OAuth success:", event.payload);
      setIsLoggedIn(true);
      setUsername(event.payload.username);
      setAvatarUrl(event.payload.avatar_url);
    });

    // エラーイベント
    const unlistenError = listen("oauth:error", (event) => {
      console.error("OAuth error:", event.payload);
    });

    return () => {
      unlistenDone.then((f) => f());
      unlistenError.then((f) => f());
    };
  }, []);

  const handleLogin = async () => {
    try {
      await invoke<number>("start_discord_login");
      // この後、ブラウザが開いて認証→リダイレクトでイベントが飛んでくる
    } catch (err) {
      console.error("Failed to start login:", err);
    }
  };

  const handleLogout = async () => {
    try {
      await invoke("logout_discord");
      setIsLoggedIn(false);
      setUsername(null);
      setAvatarUrl(null);
      console.log("Logout successful: tokens removed and state reset.");
    } catch (err) {
      console.error("Failed to logout (Rust side):", err);
    }
  };

  return (
    <div className="flex items-center space-x-2">
      {isLoggedIn && avatarUrl && (
        <img src={avatarUrl} alt="avatar" className="w-6 h-6 rounded-full" />
      )}
      {isLoggedIn && username && <span>{username}</span>}
      <button
        onClick={isLoggedIn ? handleLogout : handleLogin}
        className="px-4 py-2 bg-indigo-500 text-white rounded"
      >
        {isLoggedIn ? "ログアウト" : "Discordでログイン"}
      </button>
    </div>
  );
}