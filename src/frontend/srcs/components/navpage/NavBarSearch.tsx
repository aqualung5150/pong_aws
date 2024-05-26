import { useEffect, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";
import TempRandomMatch from "../pong/TempRandomMatch";
import styles_profile from "../../../styles/UserListStyle.module.css";
export default function Search({
  setIsLoading,
  setLeftHeader,
  setError,
  isGameConnected,
  handleGameOnOff,
  matchStartCheck,
  gameLoad,
}: {
  setIsLoading: any;
  setLeftHeader: any;
  setError: any;
  isGameConnected: any;
  matchStartCheck: boolean;
  handleGameOnOff: any;
  gameLoad: any;
}) {
  const socket = useContext(SocketContext).chatSocket;

  return (
    <div className="gameAccept-div">
      {isGameConnected && (
        <>
          <div className={styles_profile.small_div}>
            <div className={styles_profile.buttons_middle}>
              <button
                onClick={handleGameOnOff}
                className={
                  gameLoad ? styles_profile.followIn : styles_profile.unfollowIn
                }
              >
                Game
              </button>
            </div>
          </div>
          {matchStartCheck && <TempRandomMatch />}
        </>
      )}
    </div>
  );
}
