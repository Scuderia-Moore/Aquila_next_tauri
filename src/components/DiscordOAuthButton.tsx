"use client";
import { invoke } from "@tauri-apps/api/core";

export const DiscordOAuthButton = ({ onSuccess }: { onSuccess?: (token: string) => void }) => {
    const handleAuth = async () => {
        try {
            const token = await invoke<string>("start_server");
            if (token && onSuccess) {
                onSuccess(token);
            }
        } catch (err) {
            console.error("Login failed", err);
        }
    };

    return <button onClick={() => void handleAuth()}>Discordでログイン</button>;
};