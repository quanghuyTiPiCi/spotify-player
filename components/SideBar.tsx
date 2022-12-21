import {
  HomeIcon,
  HeartIcon,
  LibraryIcon,
  PlusCircleIcon,
  RssIcon,
  SearchIcon,
} from '@heroicons/react/outline';
import IconButton from './IconButton';
import { usePlaylistContext } from '../contexts/PlaylistContext';
import useSpotify from '../hooks/useSpotify';

const Divider = () => <hr className='border-t-[0.1px] border-gray-900' />;

const SideBar = () => {
  const spotifyApi = useSpotify();

  const {
    playlistContextState: { playlists },
    updatePlaylistContextState,
  } = usePlaylistContext();

  const setSelectedPlaylist = async (playlistId: string) => {
    const playlistResponse = await spotifyApi.getPlaylist(playlistId);
    updatePlaylistContextState({
      selectedPlaylistId: playlistId,
      selectedPlaylist: playlistResponse.body,
    });
  };

  return (
    <div className='text-gray-500 px-5 pt-5 pb-36 text-xs lg:text-sm border-r border-gray-900 h-screen overflow-y-scroll scrollbar-hidden  sm:max-w-[12rem] lg:max-w-[15rem] hidden md:block'>
      <div className='space-y-4'>
        <IconButton icon={HomeIcon} label='Home' />
        <IconButton icon={SearchIcon} label='Search' />
        <IconButton icon={LibraryIcon} label='Library' />
        <Divider />
        <IconButton icon={PlusCircleIcon} label='Create Playlist' />
        <IconButton icon={HeartIcon} label='Liked song' />
        <IconButton icon={RssIcon} label='Your episodes' />
        <Divider />
        {playlists.map(({ id, name }) => (
          <p
            key={id}
            className='cursor-pointer hover:text-white'
            onClick={() => {
              setSelectedPlaylist(id);
            }}
          >
            {name}
          </p>
        ))}
      </div>
    </div>
  );
};

export default SideBar;
