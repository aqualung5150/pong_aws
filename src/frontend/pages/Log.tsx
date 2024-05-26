import React, { useContext, useState, useEffect } from "react";
import { useRouter } from "next/router";
import styles from "../styles/LogStyle.module.css";

function Log() {
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [startLogin, setStartLogin] = useState(false);

  // 이미 로그인되었는지 확인
  useEffect(() => {
    sessionStorage.setItem("gamesocket", "false");
    const storedIsLoggedIn = localStorage.getItem("isLoggedIn");
    if (storedIsLoggedIn === "true") {
      setIsLoggedIn(true);
    }
  }, []);

  useEffect(() => {
    if (startLogin === true) {
      routeLogin();
    }
  }, [startLogin]);

  function Login() {
    setStartLogin(true);
  }

  function routeLogin() {
    setStartLogin(false);
    //window.location.href =
    //'https://api.intra.42.fr/oauth/authorize/?response_type=code&client_id=u-s4t2ud-7a4d91eaac011bcb231f6a2c475ff7b48445dde9311610e0db488b0f8add6fc3&redirect_uri=http://localhost/callback';
    window.location.replace(
      `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID}&redirect_uri=${process.env.NEXT_PUBLIC_GOOGLE_REDIRECT_URI}&response_type=${process.env.NEXT_PUBLIC_GOOGLE_RESPONSE_TYPE}&scope=email+profile`
    );
    // window.location.replace(
    //   `https://api.intra.42.fr/oauth/authorize/?response_type=code&client_id=${process.env.NEXT_PUBLIC_FT_CLIENT_ID}&redirect_uri=${process.env.NEXT_PUBLIC_FT_REDIRECT_URI}`
    // );
  }

  return (
    <div className={styles.mainBox}>
      {isLoggedIn ? (
        <div className={styles.innerBox}>
          <div className={styles.title2}>
            이미 로그인되었습니다. /Home 페이지로 이동합니다.
          </div>
          <button
            className={styles.button2}
            onClick={() => router.push("/Home", undefined, { shallow : true })}
          >
            {" "}
            확인
          </button>
        </div>
      ) : (
        <div className={styles.innerBox}>
          <div className={styles.title}>로그인</div>
          <button className={styles.button} onClick={Login}>
            42 로그인
          </button>
        </div>
      )}
    </div>
  );
}

export default Log;
