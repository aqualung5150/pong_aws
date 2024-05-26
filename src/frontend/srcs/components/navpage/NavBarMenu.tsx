import { useState, useContext, useEffect } from "react";
import logOutIcon from "../../../assets/logout.png";
import userIcon from "../../../assets/user.png";
import contestIcon from "../../../assets/contest.png";

import { SocketContext } from "@/context/socket";
import { GameContext } from "@/context/game";
import Image from "next/image";

import { useRouter } from "next/router";
import UserList from "../../UserList";
import MyProfile from "../../MyProfile";
import UserProfile from "../../UserProfile";
import ModalOverlay from "../modalpage/ModalOverlay";

import axiosApi from "../../AxiosInterceptor";

export default function Menu({
  setTmpLoginnickname,
}: {
  setTmpLoginnickname: any;
}) {
  const router = useRouter();
  const [myProfileModal, setMyProfileModal] = useState<boolean>(false);
  const [userListModal, setUserListModal] = useState<boolean>(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const [randomMatch, setRandomMatch] = useState<string>("");
  const [easy, setEasy] = useState<boolean>(false);
  const [normal, setNormal] = useState<boolean>(false);
  const [hard, setHard] = useState<boolean>(false);

  //seunchoi
  const isGameConnected = useContext(GameContext).isGameConnected;
  const socketContext = useContext(SocketContext);
  const gameSocket = socketContext.gameSocket;
  const [block, setBlock] = useState<boolean>(true);

  useEffect(() => {
    if (isGameConnected) {
      setBlock(false);
    }
  }, [isGameConnected]);

  useEffect(() => {
    gameSocket.on("startGame", () => {
      setRandomMatch("");
      setBlock(true);
    });
    gameSocket.on("gameOver", () => {
      setBlock(false);
    });
    gameSocket.on("matchDecline", () => {
      setRandomMatch("");
      setBlock(false);
    });
  }, [gameSocket]);

  useEffect(() => {
    // 예시로 localStorage에 isLoggedIn 상태를 저장한 것으로 가정
    const storedIsLoggedIn = localStorage.getItem("isLoggedIn");
    if (storedIsLoggedIn === "true") {
      setIsLoggedIn(true);
    } else {
      alert("로그인이 필요합니다");
      router.push("/", undefined, { shallow : true });
    }
  }, []);

  const logout = () => {
    localStorage.setItem("isLoggedIn", "false");
    localStorage.removeItem("id");
    localStorage.removeItem("nickname");
    localStorage.removeItem("is2fa");
    localStorage.removeItem("access_token");
    localStorage.removeItem("access_token_exp");
    localStorage.removeItem("avatar");
    sessionStorage.removeItem("gamesocket");
    const ApiUrl = "http://localhost:80/api/auth/logout";
    axiosApi.post(ApiUrl, {}).catch((error) => {});
    setIsLoggedIn(false);
    alert("로그아웃 되었습니다.");
    router.push("/", undefined, { shallow : true });
  };

  function handleMenu(event: any) {
    if (event.target.dataset.name) {
      if (event.target.dataset.name === "easy") {
        if (randomMatch !== "easy") {
          gameSocket.emit("randomMatchApply", "easy");
          setRandomMatch(() => "easy");
        } else {
          gameSocket.emit("randomMatchCancel");
          setRandomMatch(() => "");
        }
      } else if (event.target.dataset.name === "normal") {
        if (randomMatch !== "normal") {
          gameSocket.emit("randomMatchApply", "normal");
          setRandomMatch(() => "normal");
        } else {
          gameSocket.emit("randomMatchCancel");
          setRandomMatch(() => "");
        }
      } else if (event.target.dataset.name === "hard") {
        if (randomMatch !== "hard") {
          gameSocket.emit("randomMatchApply", "hard");
          setRandomMatch(() => "hard");
        } else {
          gameSocket.emit("randomMatchCancel");
          setRandomMatch(() => "");
        }
      }
    } else {
    }
  }
  return (
    <>
      <div className="nav-bar-menu">
        <div className="nav-bar-menu-l">
          <div className="nav-randmatch">
            <div className="dropdown">
              {/* <img
              className="dropbtn"
              src={contestIcon}
              width="35"
              height="35"
              alt="contesticon"
            /> */}
              <article className={randomMatch ? "card" : "card-no"}>
                <Image
                  className="dropbtn"
                  src={contestIcon}
                  width="35"
                  height="35"
                  alt="contesticon"
                />
                <span className={randomMatch ? "top-card" : ""}></span>
                <span className={randomMatch ? "right-card" : ""}></span>
                <span className={randomMatch ? "bottom-card" : ""}></span>
                <span className={randomMatch ? "left-card" : ""}></span>
              </article>
              {!block && (
                <div
                  onClick={() => handleMenu(event)}
                  className="dropdown-content"
                >
                  <div className="dropdown-item" data-name="easy">
                    {"RandomMatch Easy " +
                      `${randomMatch !== "easy" ? "off" : "on"}`}
                  </div>
                  <div className="dropdown-item" data-name="normal">
                    {"RandomMatch Normal " +
                      `${randomMatch !== "normal" ? "off" : "on"}`}
                  </div>
                  <div className="dropdown-item" data-name="hard">
                    {"RandomMatch Hard " +
                      `${randomMatch !== "hard" ? "off" : "on"}`}
                  </div>
                </div>
              )}
            </div>
          </div>
          <p className="nav-userlist" onClick={() => setUserListModal(true)}>
            {/* <img src={userIcon} width="30" height="30" alt="usericon" /> */}
            <Image src={userIcon} width="30" height="30" alt="usericon" />
          </p>
          <p className="nav-profile" onClick={() => setMyProfileModal(true)}>
            My
          </p>
          <p className="nav-logout">
            {/* <img src={logOutIcon} width="30" height="30" /> */}
            <Image
              src={logOutIcon}
              onClick={logout}
              width="30"
              height="30"
              alt="logouticon"
            />
          </p>
          <div>
            <>
              <ModalOverlay isOpenModal={myProfileModal} />
              {myProfileModal && (
                <>
                  <MyProfile
                    setIsOpenModal={setMyProfileModal}
                    setTmpLoginnickname={setTmpLoginnickname}
                  />
                </>
              )}
            </>
          </div>

          <div>
            <>
              <ModalOverlay isOpenModal={userListModal} />
              {userListModal && (
                <>
                  <UserList setIsOpenModal={setUserListModal} />
                </>
              )}
            </>
          </div>
        </div>
      </div>
    </>
  );
}
