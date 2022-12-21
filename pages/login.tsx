import { GetServerSideProps } from 'next';
import { getProviders, ClientSafeProvider, signIn } from 'next-auth/react';
import Head from 'next/head';
import Image from 'next/image';
import spotifyLogo from '../assets/spotify-logo.png';

interface Props {
  providers: Awaited<ReturnType<typeof getProviders>>;
}

const Login = ({ providers }: Props) => {
  const { name: providerName, id: providerId } =
    providers?.spotify as ClientSafeProvider;
  return (
    <div className='flex flex-col justify-center items-center bg-black h-screen'>
      <Head>
        <title>Login | Spotify</title>
        <meta name='description' content='Generated by create next app' />
        <meta name='viewport' content='width=device-width, initial-scale=1' />
        <link rel='icon' href='/favicon.ico' />
      </Head>
      <div className='mb-6'>
        <Image src={spotifyLogo} alt='Spotify logo' width={200} height={200} />
      </div>
      <button
        className='bg-[#18D860] text-white p-5 rounded-full'
        onClick={() => {
          signIn(providerId, { callbackUrl: '/' });
        }}
      >
        Login with {providerName}
      </button>
    </div>
  );
};
export default Login;

export const getServerSideProps: GetServerSideProps<Props> = async () => {
  const providers = await getProviders();

  return {
    props: {
      providers,
    },
  };
};