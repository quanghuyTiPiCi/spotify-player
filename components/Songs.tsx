import { usePlaylistContext } from '../contexts/PlaylistContext';
import Song from './Song';

const Songs = () => {
  const {
    playlistContextState: { selectedPlaylist },
  } = usePlaylistContext();
  if (!selectedPlaylist) return null;
  return (
    <div className='flex flex-col space-y-1 px-8 pb-28'>
      {selectedPlaylist.tracks.items.map((item, idx) => (
        <Song key={idx} item={item} itemIndex={idx} />
      ))}
    </div>
  );
};

export default Songs;
