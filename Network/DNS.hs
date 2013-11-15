{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.DNS (
     module Network.DNS.Types
   , module Network.DNS.Serializer
   , dnsServer
   , dnsMapResolver
) where

import           Control.Applicative        ((<$>))
import           Control.Concurrent
import           Control.Monad              (forever, liftM, replicateM)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.Maybe                 (mapMaybe)
import           Network.BSD
import           Network.DNS.Serializer
import           Network.DNS.Types

import qualified Data.Map                   as M
import           Network.Socket             hiding (recv, recvFrom, send,
                                             sendTo)
import           Network.Socket.ByteString

-- Simple type alias for now, in the long run
-- use a resolver typeclass?
type DNSMapResolver =  M.Map String String

-- Constructor for the resolver type
dnsMapResolver :: [(String, String)] -> DNSMapResolver
dnsMapResolver = M.fromList

--constructs an A response
answerTypeA :: DNSQuestion -> String -> DNSResource
answerTypeA DNSQuestion{..} ip = DNSResource qname A qclass 300 4 ipv4
    where ipv4 = RDA (makeIPV4 ip)

-- If there are no answers then treat this as a name error
makeResponse :: DNSHeader -> Int -> Int -> DNSHeader
makeResponse DNSHeader {..} qc 0 = DNSHeader dnsID (fl flags) { flResp = True } qc 0 0 0
    where fl DNSFlags{..} = DNSFlags True Query True False False False NameErr

makeResponse DNSHeader {..} qc ac = DNSHeader dnsID (fl flags) { flResp = True } qc ac 0 0
    where fl DNSFlags{..} = DNSFlags True Query True False False False NoErr

resolveQuestion :: DNSMapResolver -> DNSQuestion -> Maybe DNSResource
resolveQuestion m q@DNSQuestion {..} = answerTypeA q <$> M.lookup (L8.unpack qname) m

dnsReply :: Socket -> SockAddr -> DNSMapResolver -> BL.ByteString -> IO ()
dnsReply s addr mp msg = do
       let packet = runSGet msg
       let q = questions packet
       putStrLn "New request for: "
       mapM_ print q
       let ans = mapMaybe (resolveQuestion mp) q
       let hdr = makeResponse (header packet) (length q) (length ans)
       let packet' = packet { header = hdr, questions = q, answers = ans }
       let bs = runSPut packet'
       sendTo s (L8.toStrict bs) addr
       return ()

dnsServer :: PortNumber -> DNSMapResolver -> IO ()
dnsServer port dnsMap = withSocketsDo $ do
        s <- socket AF_INET Datagram defaultProtocol
        bindAddr <- inet_addr "0.0.0.0"
        bindSocket s (SockAddrInet port bindAddr)
        forever $ do
                    (msg, host) <- recvFrom s 1024
                    forkIO $ dnsReply s host dnsMap (BL.fromChunks [msg])
        sClose s

