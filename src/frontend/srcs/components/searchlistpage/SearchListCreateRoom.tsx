import { useEffect, useState, useContext } from "react";
import { SocketContext } from "@/context/socket";

export default function SearchListCreateRoom({
  setIsLoading,
  setLeftHeader,
  setError,
  query,
  setroomnameModal,
  setQuery,
}: {
  setIsLoading: any;
  setLeftHeader: any;
  setError: any;
  query: string;
  setroomnameModal: any;
  setQuery: any;
}) {
  const socket = useContext(SocketContext).chatSocket;
  const [roomname, setroomname] = useState("");
  const [disabled, setDisabled] = useState(false);

  const handleSubmit = async (event: any) => {
    setDisabled(true);
    event.preventDefault();
    if (roomname.length < 1) {
      alert("채팅창 이름 입력하세요");
    } else if (roomname[0] === "$") {
      alert("채팅창 이름의 시작은 $로 하실 수 없습니다");
    } else if (roomname.length > 14) {
      alert("채팅방 이름은 14글자 미만");
    } else {
      await new Promise((r) => setTimeout(r, 10));
      alert(`입력된 채팅창 이름: ${roomname}`);
      setroomnameModal(roomname);
      socket.emit("selectRoom", { roomname: roomname });
    }
    setroomname("");
    setQuery(() => "");
    setDisabled(false);
  };

  useEffect(
    function () {
      function fetchResults() {
        try {
          setIsLoading(true);

          if (query === "#all") {
            socket.emit("requestAllRoomList");

            setLeftHeader("all");
            setError("");
          } else if (!query) {
            socket.emit("requestMyRoomList");

            setLeftHeader("joined");

            setError("");
          } else {
            socket.emit("requestSearchResultRoomList", { target: query });

            setLeftHeader("result");
            setError("");
          }
        } catch (err: any) {
          console.error(err.message);
          setError(err.message);
        } finally {
          setIsLoading(false);
        }
      }
      fetchResults();
    },
    // [query, setError, setIsLoading, setLeftHeader, socket]
    [query, socket]
  );
  return (
    <form onSubmit={handleSubmit}>
      <div className="div-form">
        <span>
          <div className="input-search">
            <input
              type="text"
              value={roomname}
              placeholder="Create or Join room"
              onChange={(e) => {
                setroomname(e?.target.value);
                setQuery(e?.target.value);
              }}
            />
          </div>
        </span>
      </div>
    </form>
  );
}
