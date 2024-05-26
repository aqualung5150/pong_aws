import { useContext } from "react";
// import { SocketContext } from "@/context/socket";
export default function SearchSelect({
  query,
  leftHeader,
  setLeftHeader,
}: {
  query: any;
  leftHeader: any;
  setLeftHeader: any;
}) {
  return (
    <>
      <span
        data-name="all"
        className={`${leftHeader === "all" ? "selected" : ""}`}
      >
        All
      </span>
      <span> / </span>
      <span
        data-name="result"
        className={`${leftHeader === "result" ? "selected" : ""}`}
      >
        Result
      </span>
      <span> / </span>
      <span
        data-name="joined"
        className={`${leftHeader === "joined" ? "selected" : ""}`}
      >
        Joined
      </span>
    </>
  );
}
