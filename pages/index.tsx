import Head from 'next/head';
import Center from '../components/Center';
import Player from '../components/Player';
import SideBar from '../components/SideBar';
import PlaylistContextProvider from '../contexts/PlaylistContext';
import SongContextProvider from '../contexts/SongContext';

export default function Home() {
  return (
    <div className='bg-black h-screen overflow-hidden'>
      <PlaylistContextProvider>
        <SongContextProvider>
          <Head>
            <title>Spotify</title>
            <meta name='description' content='Generated by create next app' />
            <meta
              name='viewport'
              content='width=device-width, initial-scale=1'
            />
            <link rel='icon' href='/favicon.ico' />
          </Head>
          <main className='flex'>
            <SideBar />
            <Center />
          </main>
          <div className='sticky bottom-0 text-white'>
            <Player />
          </div>
        </SongContextProvider>
      </PlaylistContextProvider>
    </div>
  );
}
