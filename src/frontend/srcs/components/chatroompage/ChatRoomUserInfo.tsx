import { useEffect, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";
import menuIcon from "../../../assets/menu.png";
import ysungwonIcon from "../../../assets/ysungwon.jpg";
import ModalOverlay from "../modalpage/ModalOverlay";
import axios from "axios";
import UserProfile from "../../UserProfile";
import Image from "next/image";
import axiosApi from "@/srcs/AxiosInterceptor";

export default function ChatRoomUserInfo({
  user,
  roomInfo,
  setRoomInfo,
  roomname,
  myNickName,
  id,
  changedID,
  changedNickName,
  isGameConnected,
  isDM,
}: {
  user: any;
  roomInfo: any;
  setRoomInfo: any;
  roomname: string;
  myNickName: string;
  id: any;
  changedID: number;
  changedNickName: string;
  isGameConnected: boolean;
  isDM: boolean;
}) {
  const socket = useContext(SocketContext).chatSocket;
  const gameSocket = useContext(SocketContext).gameSocket;
  const [userProfileModal, setUserProfileModal] = useState<boolean>(false);

  function handleMenu(event: any) {
    if (event.target.dataset.name) {
      const targetnickname = user?.nickname;
      if (event.target.dataset.name === "kick") {
        socket.emit("kickUser", {
          roomname: roomname,
          target: targetnickname,
        });
      } else if (event.target.dataset.name === "profile") {
        setUserProfileModal(() => !userProfileModal);
      } else if (event.target.dataset.name === "ban") {
        socket.emit("banUser", {
          roomname: roomname,
          target: targetnickname,
        });
      } else if (event.target.dataset.name === "mute") {
        socket.emit("muteUser", {
          roomname: roomname,
          target: targetnickname,
        });
      } else if (event.target.dataset.name === "block") {
        if (targetnickname !== myNickName) {
        }
        socket.emit("blockUser", { target: targetnickname });
      } else if (event.target.dataset.name === "opAdd") {
        socket.emit("addOperator", {
          roomname: roomname,
          target: targetnickname,
        });
      } else if (event.target.dataset.name === "opDelete") {
        socket.emit("deleteOperator", {
          roomname: roomname,
          target: targetnickname,
        });
      } else if (event.target.dataset.name === "dmApply")
        socket.emit("selectDMRoom", { target: targetnickname });
      else if (event.target.dataset.name === "oneVsOneEasy") {
        gameSocket.emit("oneOnOneApply", {
          from: myNickName,
          to: targetnickname,
          mode: "easy",
        });
      } else if (event.target.dataset.name === "oneVsOneNormal") {
        gameSocket.emit("oneOnOneApply", {
          from: myNickName,
          to: targetnickname,
          mode: "normal",
        });
      } else if (event.target.dataset.name === "oneVsOneHard") {
        gameSocket.emit("oneOnOneApply", {
          from: myNickName,
          to: targetnickname,
          mode: "hard",
        });
      }
    } else {
      console.log("you click other");
    }
  }
  return (
    <>
      <li>
        <div className="userlist-avatar">
          <img
            src={`http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${
              user?.id
            }/photo?timestamp=${Date.now()}`}
            width="32"
            height="32"
            alt="avataricon"
          />
          {/* <Image
            src={`http://localhost:80/api/user/${
              user?.id
            }/photo?timestamp=${Date.now()}`}
            width="32"
            height="32"
            alt="avataricon"
          /> */}
          {/* <Image
            className="avatar-img"
            src={imgSrc}
            width="32"
            height="32"
            alt="avataricon"
          /> */}
        </div>
        <p className="userlist-username">
          {roomInfo?.owner === user?.nickname ? "🔱" : ""}
          {roomInfo?.operators.includes(user?.nickname) ? "⚜️" : ""}{" "}
          {user?.id === changedID ? changedNickName : user?.nickname}
          {user?.nickname === myNickName ? "🎆" : ""}
        </p>
        <div className="userlist-KBOM-box">
          <div className="dropdown">
            {/* <img className="dropbtn" src={menuIcon} width="15" height="15" /> */}
            <Image
              className="dropbtn"
              src={menuIcon}
              width="15"
              height="15"
              alt="menuicon"
            />
            <div onClick={() => handleMenu(event)} className="dropdown-content">
              <div className="dropdown-item" data-name="profile">
                Profile
              </div>
              {/* Operator */}
              {roomInfo?.owner !== user?.nickname &&
                !roomInfo?.operators.includes(user?.nickname) &&
                (roomInfo?.operators.includes(myNickName) ||
                  roomInfo?.owner === myNickName) &&
                user?.nickname !== myNickName && (
                  <>
                    <div className={"dropdown-item"} data-name="kick">
                      Kick
                    </div>
                    <div className="dropdown-item" data-name="ban">
                      Ban
                    </div>
                    <div className="dropdown-item" data-name="mute">
                      Mute
                    </div>
                  </>
                )}
              {/* Owner */}
              {roomInfo?.owner === myNickName &&
                user?.nickname !== myNickName && (
                  <>
                    <div className="dropdown-item dropdown-second">
                      Operator
                      <div className="dropdown-content-second">
                        <div className="dropdown-item-second" data-name="opAdd">
                          Add Operator
                        </div>
                        <div
                          className="dropdown-item-second"
                          data-name="opDelete"
                        >
                          Delete Operator
                        </div>
                      </div>
                    </div>
                  </>
                )}
              {/* Other User */}
              {user?.nickname !== myNickName && (
                <>
                  <div className="dropdown-item" data-name="block">
                    block
                  </div>
                  <div className="dropdown-item" data-name="dmApply">
                    1:1 Chat
                  </div>
                </>
              )}
              {user?.nickname !== myNickName && isGameConnected && (
                <>
                  <div className="dropdown-item dropdown-second">
                    1:1 Game
                    <div className="dropdown-content-second">
                      <div
                        className="dropdown-item-second"
                        data-name="oneVsOneEasy"
                      >
                        Easy Mode
                      </div>
                      <div
                        className="dropdown-item-second"
                        data-name="oneVsOneNormal"
                      >
                        Normal Mode
                      </div>
                      <div
                        className="dropdown-item-second"
                        data-name="oneVsOneHard"
                      >
                        Hard Mode
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
        <p className="userlist-userstatus-text">
          {(() => {
            // if (isDM) return;
            if (user?.isGaming) return "게임중";
            if (user?.isConnected) return "온라인";
            return "오프라인";
          })()}
        </p>
      </li>
      <ModalOverlay isOpenModal={userProfileModal} />
      <div>
        {userProfileModal && (
          <>
            <UserProfile id={user?.id} setIsOpenModal={setUserProfileModal} />
          </>
        )}
      </div>
    </>
  );
}
