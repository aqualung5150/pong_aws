import React, { useState, useEffect, useRef, useContext } from "react";
import { useRouter } from "next/router";
import axiosApi from "./AxiosInterceptor";
import styles_profile from "../styles/UserProfileStyle.module.css";
import { SocketContext, SocketContent } from "@/context/socket";
import "../pages/index.css";

function UserProfile({ id, setIsOpenModal }: { id: any; setIsOpenModal: any }) {
  const [userNickname, setUserNickname] = useState<string | null>(
    localStorage.getItem("nickname")
  );
  const [userId, setUserID] = useState<string | null>(
    localStorage.getItem("id")
  );
  const [userData, setData] = useState<userDataInterface[]>([]);
  const [friendList, setFriendList] = useState<string[]>([]);
  const [showProfile, setShowProfile] = useState<Boolean>(false);
  const [gameConnected, setGameConnected] = useState<boolean>(false);
  const [showMatchList, setShowMatchList] = useState(false);

  const closeModal = () => {
    setIsOpenModal(false);
  };
  const modalRef = useRef<HTMLDivElement>(null);
  const router = useRouter();

  useEffect(() => {
    // 이벤트 핸들러 함수
    const handler = () => {
      console.log("in Userprofile handler");
      if (!event) return;
      // mousedown 이벤트가 발생한 영역이 모달창이 아닐 때, 모달창 제거 처리
      const target = event.target as HTMLInputElement;
      if (modalRef.current && !modalRef.current.contains(target)) {
        setIsOpenModal(false);
      }
    };

    // 이벤트 핸들러 등록
    document.addEventListener("mousedown", handler);
    // document.addEventListener('touchstart', handler); // 모바일 대응

    return () => {
      // 이벤트 핸들러 해제
      document.removeEventListener("mousedown", handler);
      // document.removeEventListener('touchstart', handler); // 모바일 대응
    };
  });
  interface userMatchHistory {
    winner: string;
    winnerId: string;
    winnerAvatar: string;
    loser: string;
    loserId: string;
    loserAvatar: string;
    time: string;
  }

  interface userDataInterface {
    id: string;
    nickname: string;
    userProfileURL: string;
    win: number;
    lose: number;
    score: number;
    lastLogin: string;
    isFriend: number;
    isLogin: number;
    isGaming: number;
    isBlocked: number;
    matchhistory: userMatchHistory[];
  }

  const socket = useContext<SocketContent>(SocketContext).chatSocket;
  const gameSocket = useContext<SocketContent>(SocketContext).gameSocket;

  function checkIsInclude(id: string[], userid: string) {
    if (id.includes(userid.toString())) {
      return 1;
    } else {
      return 0;
    }
  }

  function logout(message: string) {
    localStorage.setItem("isLoggedIn", "false");
    localStorage.removeItem("id");
    localStorage.removeItem("nickname");
    localStorage.removeItem("is2fa");
    localStorage.removeItem("access_token");
    localStorage.removeItem("access_token_exp");
    localStorage.removeItem("avatar");
    sessionStorage.removeItem("gamesocket");
    const ApiUrl = `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/auth/logout`;
    axiosApi.post(ApiUrl, {}).catch((error: any) => {
      console.log("logout send fail: ", error); //TODO: error handling check
    });
    alert(message);
    router.push("/", undefined, { shallow: true });
  }

  useEffect(() => {
    const jwtExpItem = localStorage.getItem("access_token_exp");
    if (!jwtExpItem) {
      logout("로그인 정보가 맞지않습니다 다시 로그인해주세요.");
    }
    if (sessionStorage.getItem("gamesocket") == "true") {
      setGameConnected(true);
    }
  }, []);

  const reloadData = async () => {
    setData([]);
    setFriendList([]);
    setShowMatchList(false);

    let conList: string[] = [];
    let gameList: string[] = [];
    let blockList: string[] = [];

    function getListBySocket(data: any) {
      conList = [];
      gameList = [];
      blockList = [];
      if (data.isConnected === true) {
        conList.push(id.toString());
      }
      if (data.isGaming === true) {
        gameList.push(id.toString());
      }
      if (data.isBlocked === true) {
        blockList.push(id.toString());
      }
      console.log("socket response target connection: ", conList);
      console.log("socket response target gaming: ", gameList);
    }

    if (socket) {
      socket.emit("requestTargetMember", { targetId: id });
      socket.once("responseTargetMember", async (data: any) =>
        getListBySocket(data)
      );
    }

    let idList: string[] = [];
    //const responseFriend = await (await fetch_refresh ('http://localhost/api/user/' + userId + '/friend')).json();
    const responseData = await axiosApi.get(
      `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${userId}/friend`
    );
    const responseFriend = responseData.data;
    const friendCount = responseFriend.friendList.length;
    for (let i = 0; i < friendCount; i++) {
      idList.push(responseFriend.friendList[i].id.toString());
    }
    setFriendList(idList);

    const newDataList: userDataInterface[] = [];
    const responseDetail = await axiosApi.get(
      `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${id}`
    );
    const detailResponse = responseDetail.data;
    const responseMatch = await axiosApi.get(
      `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${id}/matchhistory`
    );
    const matchResponse = responseMatch.data;
    const matchCount = matchResponse.length;
    const newData: userDataInterface = {
      id: detailResponse.id,
      nickname: detailResponse.nickname,
      userProfileURL: `/api/user/${id}/photo?timestamp=${Date.now()}`,
      win: detailResponse._count.asWinner,
      lose: detailResponse._count.asLoser,
      score: detailResponse.score,
      lastLogin: detailResponse.lastLogin,
      isFriend: checkIsInclude(idList, detailResponse.id),
      //isLogin: checkIsInclude(conList, detailResponse.id),
      isLogin: 1,
      isGaming: checkIsInclude(gameList, detailResponse.id),
      //isGaming: 1,
      isBlocked: checkIsInclude(blockList, detailResponse.id),
      matchhistory: [],
    };
    for (let j = 0; j < matchCount; j++) {
      const newMatchData: userMatchHistory = {
        winner: matchResponse[j].winner.nickname,
        winnerId: matchResponse[j].winner.id,
        winnerAvatar: `/api/photo/${matchResponse[j].winner.avatar}`,
        loser: matchResponse[j].loser.nickname,
        loserId: matchResponse[j].loser.id,
        loserAvatar: `/api/photo/${matchResponse[j].loser.avatar}`,
        time: matchResponse[j].createdTime,
      };
      newMatchData.time = newMatchData.time.slice(0, 19);
      newMatchData.time = newMatchData.time.replace("T", " ");
      newData.matchhistory.push(newMatchData);
    }
    newDataList.push(newData);
    setData(newDataList);
    setShowProfile(true);
  };

  function openMatchList() {
    setShowMatchList(!showMatchList);
  }

  function sendMatch(level: string) {
    setUserNickname(localStorage.getItem("nickname"));
    console.log(
      "sendMatch: " + userNickname + " " + userData[0].nickname + " " + level
    );
    gameSocket.emit("oneOnOneApply", {
      from: userNickname,
      to: userData[0].nickname,
      mode: level,
    });
    alert(userData[0].nickname + "님에게 게임 신청이 전송되었습니다");
  }

  function blockUser() {
    //let copiedData = [...userData];
    if (userData[0].isBlocked == 0) {
      //copiedData[0].isBlocked = 1;
      socket.emit("blockUser", { target: userData[0].nickname });
      if (userData[0].isFriend == 1) {
        unFollow(0);
      }
    } else if (userData[0].isBlocked == 1) {
      //copiedData[0].isBlocked = 0;
      socket.emit("unblockUser", { target: userData[0].nickname });
    }
    //setData(copiedData);
  }

  async function follow(index: number) {
    const apiUrl = `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${userId}/friend`;
    const dataToUpdate = {
      isAdd: true,
      friend: Number(userData[0].id),
    };

    await axiosApi
      .patch(apiUrl, JSON.stringify(dataToUpdate), {
        headers: {
          "Content-Type": "application/json",
        },
      })
      .then((response) => {
        if (response.data.error) {
          alert("Follow에 실패했습니다");
        } else {
          console.log("Follow 성공 데이터:", response.data);
          let copiedData = [...userData];
          copiedData[index].isFriend = 1;
          setData(copiedData);
        }
      })
      .catch((error) => {
        alert("Follow에 실패했습니다");
      });
  }
  async function unFollow(index: number) {
    const apiUrl = `http://${process.env.NEXT_PUBLIC_BASE_URL}/api/user/${userId}/friend`;
    const dataToUpdate = {
      isAdd: false,
      friend: userData[0].id,
    };

    await axiosApi
      .patch(apiUrl, JSON.stringify(dataToUpdate), {
        headers: {
          "Content-Type": "application/json",
        },
      })
      .then((response) => {
        if (response.data.error) {
          alert("UnFollow에 실패했습니다");
        } else {
          console.log("UnFollow 성공 데이터:", response.data);
          let copiedData = [...userData];
          copiedData[index].isFriend = 0;
          setData(copiedData);
        }
      })
      .catch((error) => {
        alert("UnFollow에 실패했습니다");
      });
  }

  useEffect(() => {
    setUserID(localStorage.getItem("id"));
    reloadData();
  }, []);

  useEffect(() => {
    async function reloadStatus(userId: number, isConnected: boolean) {
      console.log("Status Update! " + userId + isConnected);
      if (isConnected === true) {
        let copiedData = [...userData];
        for (let i = 0; i < copiedData.length; i++) {
          if (copiedData[i].id == userId.toString()) {
            copiedData[i].isLogin = 1;
            break;
          }
        }
        setData(copiedData);
      } else {
        let copiedData = [...userData];
        for (let i = 0; i < copiedData.length; i++) {
          if (copiedData[i].id == userId.toString()) {
            copiedData[i].isLogin = 0;
            break;
          }
        }
        setData(copiedData);
      }
    }

    async function reloadNick(userId: number, newNick: string) {
      let copiedData = [...userData];
      console.log("Nickname Update! " + userId + newNick);
      for (let i = 0; i < userData.length; i++) {
        const matchCount = copiedData[i].matchhistory.length;
        for (let j = 0; j < matchCount; j++) {
          if (copiedData[i].matchhistory[j].winnerId == userId.toString())
            copiedData[i].matchhistory[j].winner = newNick;
          else if (copiedData[i].matchhistory[j].loserId == userId.toString())
            copiedData[i].matchhistory[j].loser = newNick;
        }
      }
      for (let i = 0; i < userData.length; i++) {
        if (userData[i].id == userId.toString()) {
          copiedData[i].nickname = newNick;
          break;
        }
      }
      if (copiedData != null) {
        setData(copiedData);
      }
    }

    async function reloadAvatar(userId: number) {
      console.log("Avatar Update! " + userId);
      let copiedData = [...userData];
      for (let i = 0; i < userData.length; i++) {
        if (copiedData[i].id == userId.toString()) {
          copiedData[
            i
          ].userProfileURL = `/api/user/${userId}/photo?timestamp=${Date.now()}`;
        }
        const matchCount = copiedData[i].matchhistory.length;
        for (let j = 0; j < matchCount; j++) {
          if (copiedData[i].matchhistory[j].winnerId == userId.toString())
            copiedData[i].matchhistory[
              j
            ].winnerAvatar = `/api/user/${userId}/photo?timestamp=${Date.now()}`;
          else if (copiedData[i].matchhistory[j].loserId == userId.toString())
            copiedData[i].matchhistory[
              j
            ].loserAvatar = `/api/user/${userId}/photo?timestamp=${Date.now()}`;
        }
      }
      if (copiedData != null) {
        setData(copiedData);
      }
    }
    async function reloadGameStatusIn(userId: any) {
      console.log(`${userId} is in game!!`);
      let copiedData = null;
      for (let i = 0; i < userData.length; i++) {
        if (userData[i].id == userId) {
          let copiedData = [...userData];
          copiedData[i].isGaming = 1;
          break;
        }
      }
      if (copiedData != null) {
        setData(copiedData);
      }
    }
    async function reloadGameStatusOut(userId: any) {
      console.log(`${userId} is not in game!!`);
      let copiedData = null;
      for (let i = 0; i < userData.length; i++) {
        if (userData[i].id == userId) {
          let copiedData = [...userData];
          copiedData[i].isGaming = 0;
          break;
        }
      }
      if (copiedData != null) {
        setData(copiedData);
      }
    }

    async function reloadFollowStatus(targetId: number) {
      console.log(`${targetId} / friend status update`);
      let copiedData = [...userData];
      for (let i = 0; i < userData.length; i++) {
        if (userData[i].id == targetId.toString()) {
          copiedData[i].isFriend = 1;
        }
      }
      setData(copiedData);
    }

    async function reloadUnFollowStatus(targetId: number) {
      console.log(`${targetId} / friend status update`);
      let copiedData = [...userData];
      for (let i = 0; i < userData.length; i++) {
        if (userData[i].id == targetId.toString()) {
          copiedData[i].isFriend = 0;
        }
      }
      setData(copiedData);
    }

    async function reloadBlockStatus(targetId: number) {
      console.log("block update!:", targetId);
      let copiedData = [...userData];
      for (let i = 0; i < userData.length; i++) {
        //copiedData[i].isBlocked = checkIsInclude(result, copiedData[i].id);
        if (userData[i].id == targetId.toString()) {
          if (copiedData[i].isBlocked == 0) {
            copiedData[i].isBlocked = 1;
          } else if (copiedData[i].isBlocked == 1) {
            copiedData[i].isBlocked = 0;
          }
        }
      }
      setData(copiedData);
    }

    if (socket) {
      if (socket) {
        socket.on("updateUserStatus", reloadStatus);
        socket.on("updateUserNick", reloadNick);
        socket.on("updateUserAvatar", reloadAvatar);
        socket.on("follow", reloadFollowStatus);
        socket.on("unfollow", reloadUnFollowStatus);
        socket.on("updateBlocklist", reloadBlockStatus);
        socket.on("inGame", reloadGameStatusIn);
        socket.on("NotInGame", reloadGameStatusOut);
      }
      return () => {
        if (socket) {
          socket.off("updateUserStatus", reloadStatus);
          socket.off("updateUserNick", reloadNick);
          socket.off("updateUserAvatar", reloadAvatar);
          socket.off("follow", reloadFollowStatus);
          socket.off("unfollow", reloadUnFollowStatus);
          socket.off("updateBlocklist", reloadBlockStatus);
          socket.off("inGame", reloadGameStatusIn);
          socket.off("NotInGame", reloadGameStatusOut);
        }
      };
    }
  }, [socket, userData, gameSocket]);

  function getDetailProfile() {
    return (
      <>
        <div className={styles_profile.mainBox}>
          <div className={styles_profile.profileInner}>
            <div className={styles_profile.imageBox}>
              <img
                src={userData[0].userProfileURL}
                alt="profile img"
                className={styles_profile.profileImage}
              />
              {userData[0].id == userId && (
                <div className={styles_profile.circleMine}></div>
              )}
              {userData[0].id != userId && userData[0].isLogin === 0 && (
                <div className={styles_profile.circleLogout}></div>
              )}
              {userData[0].id != userId && userData[0].isLogin === 1 && (
                <div className={styles_profile.circleLogin}></div>
              )}
            </div>
            <div>
              <h2>{userData[0].nickname}의 프로필</h2>
            </div>
            <br />
            <br />
            <br />
            <br />
            <br />
            <div className={styles_profile.wlsBanner}>
              Win / Lose / Total Score
            </div>
            <div>
              <h2>
                {userData[0].win} / {userData[0].lose} / {userData[0].score}
              </h2>
            </div>
            <div className={styles_profile.buttons}>
              {userData[0].isBlocked === 1 && (
                <button className={styles_profile.disabled}>차단 중</button>
              )}
              {userData[0].id != userId &&
                userData[0].isFriend === 0 &&
                userData[0].isBlocked === 0 && (
                  <button
                    className={styles_profile.followButton}
                    onClick={() => {
                      follow(0);
                    }}
                  >
                    {" "}
                    팔로우{" "}
                  </button>
                )}
              {userData[0].id != userId &&
                userData[0].isFriend === 1 &&
                userData[0].isBlocked === 0 && (
                  <button
                    className={styles_profile.followingButton}
                    onClick={() => {
                      unFollow(0);
                    }}
                  >
                    {" "}
                    언팔로우{" "}
                  </button>
                )}
              {userData[0].id != userId && userData[0].isLogin == 0 && (
                <button className={styles_profile.disabled}>미 접속</button>
              )}
              {userData[0].id != userId &&
                userData[0].isLogin == 1 &&
                userData[0].isBlocked == 1 && (
                  <button className={styles_profile.disabled}>차단 중</button>
                )}
              {userData[0].id != userId &&
                userData[0].isGaming == 0 &&
                userData[0].isLogin == 1 &&
                userData[0].isBlocked == 0 &&
                gameConnected == true && (
                  <button
                    className={styles_profile.gameButton}
                    onClick={() => {
                      openMatchList();
                    }}
                  >
                    게임 신청
                  </button>
                )}
              {userData[0].id != userId &&
                userData[0].isGaming == 0 &&
                userData[0].isLogin == 1 &&
                userData[0].isBlocked == 0 &&
                gameConnected == false && (
                  <button className={styles_profile.disabled}>게임 신청</button>
                )}
              {userData[0].id != userId &&
                userData[0].isGaming == 1 &&
                userData[0].isLogin == 1 &&
                userData[0].isBlocked == 0 && (
                  <button className={styles_profile.disabled}>게임 중</button>
                )}
            </div>
            <div className={styles_profile.buttons}>
              {userData[0].id != userId && userData[0].isBlocked == 0 && (
                <button
                  className={styles_profile.blockButton}
                  onClick={() => {
                    blockUser();
                  }}
                >
                  차단
                </button>
              )}
              {userData[0].id != userId && userData[0].isBlocked == 1 && (
                <button
                  className={styles_profile.unblockButton}
                  onClick={() => {
                    blockUser();
                  }}
                >
                  차단 해제
                </button>
              )}
              {showMatchList && (
                <div className={styles_profile.gameButtons}>
                  <button
                    onClick={() => {
                      sendMatch("easy");
                    }}
                  >
                    {" "}
                    EASY{" "}
                  </button>
                  <button
                    onClick={() => {
                      sendMatch("normal");
                    }}
                  >
                    {" "}
                    NORMAL{" "}
                  </button>
                  <button
                    onClick={() => {
                      sendMatch("hard");
                    }}
                  >
                    {" "}
                    HARD{" "}
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className={styles_profile.logInner}>
            <div className={styles_profile.logBanner}>
              <h1>최근 전적</h1>
              {userData[0].matchhistory.slice(0, 10).map((item, idx) => (
                <div key={idx} className={styles_profile.logBox}>
                  <div className={styles_profile.logTime}>
                    {userData[0].matchhistory[idx].time.slice(0, 10)}
                    <br />
                    {userData[0].matchhistory[idx].time.slice(11, 19)}
                  </div>
                  <div className={styles_profile.logName}>
                    {userData[0].matchhistory[idx].winner}
                  </div>
                  <img
                    src={userData[0].matchhistory[idx].winnerAvatar}
                    alt="profile img"
                    className={styles_profile.logProfileImage}
                  />
                  <div className={styles_profile.resultFont}>승</div>
                  <div className={styles_profile.resultFont}>패</div>
                  <img
                    src={userData[0].matchhistory[idx].loserAvatar}
                    alt="profile img"
                    className={styles_profile.logProfileImage}
                  />
                  <div className={styles_profile.logName}>
                    {userData[0].matchhistory[idx].loser}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </>
    );
  }

  function getDetailProfileBox() {
    return <div className={styles_profile.fontSet}>{getDetailProfile()}</div>;
  }

  return (
    <div ref={modalRef} className="modal modal-userprofile">
      {showProfile && getDetailProfileBox()}
    </div>
  );
}

export default UserProfile;
