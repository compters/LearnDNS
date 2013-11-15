{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.DNS.Serializer where

import           Control.Applicative
import           Control.Monad
import qualified Control.Monad.State        as S
import           Data.Binary
import           Data.Binary.Get
import           Data.Binary.Put
import           Data.Bits
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Char8      as C8
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as BL8
import           Data.IntMap                (IntMap)
import qualified Data.IntMap                as IM
import qualified Data.Map                   as M
import           Data.Monoid
import           Data.Word
import           Network.DNS.Types

class PBinary a where
   pput :: a -> SPut
   pget :: SGet a

runSGet :: PBinary a => BL.ByteString -> a
runSGet = fst . runGet (S.runStateT pget rstate)

-- evalSGet :: SGet a -> BL.ByteString -> a
-- evalSGet g = runGet (S.evalStateT g rstate)

runSPut :: PBinary a => a -> BL.ByteString
runSPut a = runPut $ S.evalStateT (pput a) wstate

-- evalS :: SPut -> BL.ByteString
-- evalS p = runPut $ S.evalStateT p wstate

rdLength :: RData -> Int
rdLength (RDA ip) = 8 * length ip
rdLength (RDNS d) = (fromIntegral . BL8.length $ d) + 1
rdLength (RDCName d) = (fromIntegral . BL8.length $ d) + 1
rdLength (RDPtr d) = (fromIntegral . BL8.length $ d) + 1

instance PBinary DNSQuestion where
    pget = do
        name <- readDomain
        let qname = runGet (getName []) name
        qtype <- readInt16
        qclass <- readInt16
        return $ DNSQuestion qname (toEnum qtype) qclass

    pput DNSQuestion{..} = do
        writeDomain qname
        writeInt16 $ fromEnum qtype
        writeInt16 qclass

instance PBinary DNSResource where
    pget = do
        rname <- readDomain
        rtype <- toEnum <$> readInt16
        rclass <- readInt16
        rttl <- readInt32
        rdlength <- readInt16
        rdata <- getRData rtype
        return $ DNSResource rname rtype rclass rttl rdlength rdata

    pput DNSResource{..} = do
        writeDomain rname
        writeInt16 $ fromEnum rtype
        writeInt16 rclass
        writeInt32 rttl
        writeInt16 rdlength
        putRData rdata

getRData :: TYPE -> SGet RData
getRData A = RDA <$> replicateM 4 readInt8
getRData NS = RDNS <$> readDomain
getRData CNAME = RDCName <$> readDomain
getRData PTR = RDPtr <$> readDomain
getRData _ = RDNS <$> readDomain

putRData :: RData -> SPut
putRData (RDA ipv4)   = writeIPV4 ipv4
putRData (RDNS ns)    = writeDomain ns
putRData (RDCName cn) = writeDomain cn
putRData (RDPtr p)    = writeDomain p

instance PBinary DNSPacket where
    pget = do
        header <- pget
        questions <- parseMany (qdcount header)
        answers <- parseMany (ancount header)
        authority <- parseMany (nscount header)
        additional <- parseMany (arcount header)
        return $ DNSPacket header questions answers authority additional

    pput DNSPacket{..} = do
        pput header
        mapM_ pput questions
        mapM_ pput answers
        mapM_ pput authority
        mapM_ pput additional

writeIPV4 :: IPV4 -> SPut
writeIPV4 = mapM_ writeInt8

getPointer :: Get (Maybe Int)
getPointer = do
    ptr <- getInt16
    if (ptr .&. 0xc000) /= 0xc000 then
        return Nothing
    else do
         let val = ptr `xor` 0xc000
         return $ Just val

instance PBinary Pointer where
   pget = do
       ptr <- readInt16
       when ((ptr .&. 0xc000) /= 0xc000) $ fail "Not pointer"
       let val = ptr `xor` 0xc000
       return $ Pointer val ""

   pput Pointer{..} = writeInt16 $ pOffset .|. 0xc000

writeDomain :: Domain -> SPut
writeDomain d = do
    (WState m _) <- S.get
    case M.lookup d m of
        Just ptr -> pput (Pointer ptr "")
        Nothing  -> do
                      recordDomain d
                      writeLazyByteStringNul (packName d)
    where
       recordDomain :: Domain -> SPut
       recordDomain dm = do
          (WState m p) <- S.get
          let m' = M.insert dm p m
          S.put (WState m' p)

readDomain :: SGet Domain
readDomain = do
    mPtr <- S.lift $ lookAheadM getPointer
    case mPtr of
        Just ptr -> lookupDomain ptr
        Nothing  -> do
                       (RState _ p) <- S.get
                       d <- readLazyByteStringNul
                       recordDomain d p
    where
        lookupDomain :: Int -> SGet Domain
        lookupDomain ptr = do
            (RState m _) <- S.get
            return $ m IM.! ptr

        recordDomain :: Domain -> Int -> SGet Domain
        recordDomain d ptr = do
            (RState m p') <- S.get
            return d <* S.put (RState (IM.insert ptr d m) p')


instance PBinary DNSHeader where
    pget = DNSHeader <$> readWord16
                     <*> pget
                     <*> readInt16
                     <*> readInt16
                     <*> readInt16
                     <*> readInt16

    pput DNSHeader{..} = do
        writeWord16 dnsID
        pput flags
        writeInt16 qdcount
        writeInt16 ancount
        writeInt16 nscount
        writeInt16 arcount

instance PBinary DNSFlags where
   pget = do
        flags <- readInt16
        let isResp = testBit flags 15
        let opCode = fromIntegral $ shiftR flags 11 .&. 0x0f
        let aa = bt flags 10
        let tc = bt flags 9
        let rd = bt flags 8
        let ra = bt flags 7
        let rcode = flags .&. 0x0f
        return $ DNSFlags isResp (toEnum opCode) aa tc rd ra (toEnum rcode)

   pput dns = writeWord16 $ getWord dns
        where
           getWord  :: DNSFlags -> Word16
           getWord DNSFlags{..} = flagWord
              where
                opcode :: Word16
                opcode = shiftL (fromIntegral $ fromEnum flOpcode) 11
                rcode :: Word16
                rcode = fromIntegral (fromEnum flRcode)
                flagWord :: Word16
                flagWord = st 15 flResp .|. opcode .|. st 10 flAa .|. st 9 flTc .|. st 8 flRd .|. st 7 flRa .|. rcode

bt :: Int -> Int -> Bool
bt = testBit

st :: Int -> Bool -> Word16
st idx True = bit idx
st _ False = 0

incPosR :: Int -> SGet ()
incPosR amnt = do
   RState m p <- S.get
   S.put $ RState m (p + amnt)

incPosW :: Int -> SPut
incPosW amnt = do
   WState m p <- S.get
   S.put $ WState m (p + amnt)

writeSized :: Int -> (a -> PutM ()) -> a -> SPut
writeSized s f x = do
                      incPosW s
                      S.lift (f x)

readSized :: Int -> Get a -> SGet a
readSized s f = S.lift f <* incPosR s

readWord16 :: SGet Word16
readWord16 = readSized 4 getWord16be

readInt32 :: SGet Int
readInt32 = readSized 4 (fromIntegral <$> getWord32be)

readInt16 :: SGet Int
readInt16 = readSized 2 (fromIntegral <$> getWord16be)

readInt8 :: SGet Int
readInt8 = readSized 1 (fromIntegral <$> getWord8)

readByteString :: Int -> SGet BS.ByteString
readByteString len = readSized (len `div` 8) $ getByteString len

readLazyByteString :: Int -> SGet BL.ByteString
readLazyByteString len = readSized (len `div` 8) $ getLazyByteString (fromIntegral len)

readLazyByteStringNul :: SGet BL.ByteString
readLazyByteStringNul = do
    bs <- S.lift getLazyByteStringNul
    incPosR (fromIntegral $ BL.length bs + 1 `div` 8)
    return bs

writeLazyByteString :: BL.ByteString -> SPut
writeLazyByteString bs = writeSized (fromIntegral $ BL.length bs `div` 8) putLazyByteString bs

writeLazyByteStringNul :: BL.ByteString -> SPut
writeLazyByteStringNul bs = do
                       writeSized (fromIntegral $ BL.length bs + 1 `div` 8) putLazyByteString bs
                       S.lift $ putLazyByteString (BL.singleton 0)

writeByteString :: BS.ByteString -> SPut
writeByteString bs = writeSized (fromIntegral $ BS.length bs `div` 8) putByteString bs

writeInt8 :: Int -> SPut
writeInt8 x = writeSized 1 putWord8 (fromIntegral x)

writeInt16 :: Int -> SPut
writeInt16 x = writeSized 2 putWord16be (fromIntegral x)

writeInt32 :: Int -> SPut
writeInt32 x = writeSized 4 putWord32be (fromIntegral x)

writeWord16 :: Word16 -> SPut
writeWord16 = writeSized 2 putWord16be

getName :: [C8.ByteString] -> Get BL.ByteString
getName x = do
    empty <- isEmpty
    if empty then return (BL.fromStrict . C8.intercalate "." . reverse $ x)
    else  do
            len <- getInt8
            bs <- getByteString len
            getName (bs : x)

getInt32 :: Get Int
getInt32 = liftM fromIntegral getWord32be

getInt8 :: Get Int
getInt8 = liftM fromIntegral getWord8

getInt16 :: Get Int
getInt16 =  fromIntegral <$> getWord16be

putInt16 :: Int -> Put
putInt16 = putWord16be . fromIntegral

putInt32 :: Int -> Put
putInt32 = putWord32be . fromIntegral

parseMany :: PBinary a => Int -> SGet [a]
parseMany 0 = return []
parseMany n = replicateM n pget

packName :: Domain -> Domain
packName name = BL8.concat $ map prependLength $ BL8.split '.' name
    where
        prependLength s = BL8.concat [bsLen s, s]
        bsLen :: BL8.ByteString -> BL8.ByteString
        bsLen = BL.singleton .fromIntegral . BL.length
