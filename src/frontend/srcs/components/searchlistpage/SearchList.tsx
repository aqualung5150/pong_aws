import { useEffect, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";

import SearchListCreateRoom from "./SearchListCreateRoom";

import SearchListMain from "./SearchListMain";

export default function SearchList({
  results,

  leftHeader,
  isOpenModal,
  blocklist,
  currentRoomName,
  lastMessageList,
  setLastMessageList,
  setError,
  setIsLoading,

  setLeftHeader,
  setroomnameModal,
  setIsOpenModal,
  setTempSearchList,
  setCurrentRoomName,
}: {
  results: any;

  leftHeader: any;
  setLeftHeader: any;
  setroomnameModal: any;
  isOpenModal: boolean;
  setIsOpenModal: any;
  setTempSearchList: any;
  blocklist: any;
  currentRoomName: string;
  setCurrentRoomName: any;
  lastMessageList: any;
  setLastMessageList: any;
  setError: any;
  setIsLoading: any;
}) {
  const socket = useContext(SocketContext).chatSocket;
  const [query, setQuery] = useState("");
  useEffect(() => {
    function requestPassword(roomname: string) {
      alert(`<${roomname}> 방의 비밀번호를 입력하세요 `);
      setIsOpenModal(true);
    }
    function sendRoomList(newResults: any) {
      let max = lastMessageList;

      max.forEach((value: any, key: any) => {});
      newResults.map((result: any) => {
        let chkNew;
        if (!max.get(result.roomname)) {
          result.messageNew = true;
          max.set(result.roomname, {
            fromId: result?.fromId,
            lastMessage: result?.lastMessage,
            messageNew: true,
            at: result?.at,
          });
        }
        if (currentRoomName === result.roomname) {
          result.messageNew = false;
          max.set(result.roomname, {
            fromId: result?.fromId,
            lastMessage: result.lastMessage,
            messageNew: false,
            at: result?.at,
          });
          return result;
        } else {
          if (
            max.get(result.roomname)?.at === result?.at &&
            result.messageNew === false
          ) {
            result.messageNew = false;
            max.set(result.roomname, {
              fromId: result?.fromId,
              lastMessage: result.lastMessage,
              messageNew: false,
              at: result?.at,
            });
            return result;
          } else if (
            max.get(result.roomname)?.at === result?.at &&
            result.messageNew === true
          ) {
            result.messageNew = true;
            max.set(result.roomname, {
              fromId: result?.fromId,
              lastMessage: result.lastMessage,
              messageNew: true,
              at: result?.at,
            });
            return result;
          } else if (max.get(result.roomname)?.at !== result?.at) {
            result.messageNew = true;
            max.set(result.roomname, {
              fromId: result?.fromId,
              lastMessage: result.lastMessage,
              messageNew: true,
              at: result?.at,
            });
            return result;
          }
        }
      });
      max.forEach((value: any, key: any) => {});

      setLastMessageList(() => max);
      setTempSearchList(() => newResults);
    }
    function responseRoomQuery(result: any) {
      setTempSearchList(() => result);
    }

    socket.on("sendRoomList", sendRoomList);
    socket.on("requestPassword", requestPassword);
    socket.on("responseRoomQuery", responseRoomQuery);

    return () => {
      socket.off("responseRoomQuery", responseRoomQuery);
      socket.off("sendRoomList", sendRoomList);
      socket.off("requestPassword", requestPassword);
    };
  }, [socket, isOpenModal, results, currentRoomName, lastMessageList]);

  return (
    <>
      <div className="wrp">
        <SearchListMain
          results={results}
          query={query}
          blocklist={blocklist}
          leftHeader={leftHeader}
          setLeftHeader={setLeftHeader}
          setroomnameModal={setroomnameModal}
          setCurrentRoomName={setCurrentRoomName}
          setError={setError}
          setIsLoading={setIsLoading}
          setQuery={setQuery}
        />
      </div>
    </>
  );
}
