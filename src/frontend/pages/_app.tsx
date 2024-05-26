import { AppProps } from 'next/app'; // AppProps 타입 불러오기

function MyApp({ Component, pageProps }: AppProps) {
  // Component: 현재 페이지 컴포넌트
  // pageProps: 페이지 컴포넌트에 전달되는 props

  // 공통 레이아웃 및 로직 설정

  return <Component {...pageProps} />;
}

export default MyApp;
