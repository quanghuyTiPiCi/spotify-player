import { ChevronDownIcon, UserIcon } from '@heroicons/react/outline';
import { signOut, useSession } from 'next-auth/react';
import Image from 'next/image';
import { usePlaylistContext } from '../contexts/PlaylistContext';
import Icon from '../assets/spotify-logo.png';
import { useEffect, useState } from 'react';
import { pickRandom } from '../utils/pickRandomColour';
import Song from './Songs';
import Songs from './Songs';

const colours = [
  'from-indigo-500',
  'from-blue-500',
  'from-green-500',
  'from-red-500',
  'from-purple-500',
  'from-pink-500',
  'from-yellow-500',
];

const Center = () => {
  const {
    playlistContextState: { selectedPlaylistId, selectedPlaylist },
  } = usePlaylistContext();

  const { data: session } = useSession();

  const [fromColour, setFormColour] = useState<string | null>(null);

  useEffect(() => {
    setFormColour(pickRandom(colours));
  }, [selectedPlaylistId]);

  return (
    <div className='flex-grow text-white relative h-screen overflow-y-scroll scrollbar-hidden'>
      <header className='absolute top-5 right-8'>
        <div
          className='flex items-center bg-black space-x-3 opacity-90 hover:opacity-80 cursor-pointer rounded-full py-1 pl-1 pr-2'
          onClick={() => {
            signOut();
          }}
        >
          <Image
            src={session?.user?.image || Icon}
            alt=''
            height={40}
            width={40}
            className='rounded-full object-cover'
          />
          <h2>{session?.user?.name}</h2>
          <ChevronDownIcon className='icon' />
        </div>
      </header>
      <section
        className={`flex items-end space-x-7 bg-gradient-to-b ${fromColour} to-black h-80 p-8`}
      >
        {selectedPlaylist && (
          <>
            <Image
              src={selectedPlaylist.images[0].url}
              alt=''
              height={176}
              width={176}
              className='shadow-2xl'
            />
            <div>
              <p>PLAYLIST</p>
              <h1 className='text-2xl font-bold md:text-3xl xl:text-5xl'>
                {selectedPlaylist.name}
              </h1>
            </div>
          </>
        )}
      </section>
      <div>
        <Songs />
      </div>
    </div>
  );
};

export default Center;
