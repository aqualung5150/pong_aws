import { useState, useEffect } from "react";

export default function GameListHeader({
  myNickName,
  page,
  setPage,
  leftArrow,
  rightArrow,
}: {
  myNickName: string;
  page: number;
  setPage: any;
  leftArrow: boolean;
  rightArrow: boolean;
}) {
  return (
    <div className="gamelist-header">
      <h4>Inception</h4>

      <button
        onClick={() => setPage(() => page - 1)}
        className={`btn-page ${leftArrow ? "" : "visible"}`}
      >
        &larr;
      </button>
      <button
        onClick={() => setPage(() => page + 1)}
        className={`btn-page ${rightArrow ? "" : "visible"}`}
      >
        &rarr;
      </button>
    </div>
  );
}
