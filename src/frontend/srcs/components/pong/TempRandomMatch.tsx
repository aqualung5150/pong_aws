import { GameContent, GameContext } from "@/context/game";
import { SocketContent, SocketContext } from "@/context/socket";
import React, { useContext, useState, useEffect } from "react";
import { AutoSave } from "./Pong";
import styles_profile from "../../../styles/UserProfileStyle.module.css";
export default function TempRandomMatch() {
  const roomName = useContext(GameContext).roomName;
  const socket = useContext(SocketContext).gameSocket;

  const handleAccept = () => {
    console.log(roomName + "Clicked");
    socket.emit("matchAccept", `${roomName}`);
  };

  const handleDecline = () => {
    socket.emit("matchDecline", `${roomName}`);
  };

  return (
    <div className={styles_profile.small_div}>
      <div className={styles_profile.buttons_middle}>
        <button className={styles_profile.gameButton} onClick={handleAccept}>
          수락
        </button>
        <button className={styles_profile.blockButton} onClick={handleDecline}>
          거절
        </button>
      </div>
    </div>
  );
}
