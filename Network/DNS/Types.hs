{-# LANGUAGE OverloadedStrings #-}

module Network.DNS.Types where

import qualified Control.Monad.State  as S
import           Data.Binary
import           Data.Binary.Get      ()
import           Data.Binary.Put
import qualified Data.ByteString.Lazy as BL
import           Data.IntMap          (IntMap)
import qualified Data.IntMap          as IM
import           Data.List.Split      (splitOn)
import qualified Data.Map             as M
import           Data.Maybe           (mapMaybe)

type Domain = BL.ByteString

data TYPE = A | AAAA | NS | TXT | MX | CNAME | SOA | PTR | SRV
          | UNKNOWN Int deriving (Eq, Show, Read)

data Pointer = Pointer { pOffset :: Int, pRecord :: Domain }
    deriving (Show, Eq)

instance Enum TYPE where
   fromEnum A = 1
   fromEnum NS = 2
   fromEnum CNAME = 5
   fromEnum SOA = 6
   fromEnum PTR = 12
   fromEnum MX = 15
   fromEnum TXT = 16
   fromEnum AAAA = 28
   fromEnum SRV = 33
   fromEnum (UNKNOWN x) = x

   toEnum 1 = A
   toEnum 2 = NS
   toEnum 5 = CNAME
   toEnum 6 = SOA
   toEnum 12 = PTR
   toEnum 15 = MX
   toEnum 16 = TXT
   toEnum 28 = AAAA
   toEnum 33 = SRV
   toEnum x = UNKNOWN x

data OpCode =  Query
             | IQuery
             | ServerStatus
             | Reserved Int
   deriving (Show, Eq)

instance Enum OpCode where
    fromEnum Query = 0
    fromEnum IQuery = 1
    fromEnum ServerStatus = 2
    fromEnum (Reserved r) = r

    toEnum 0 = Query
    toEnum 1 = IQuery
    toEnum 2 = ServerStatus
    toEnum r = Reserved r

type IPV4 = [Int]

tryParse :: String -> Maybe Int
tryParse s = case reads s of
              [(i, _)] ->  Just i
              _        ->  Nothing

makeIPV4 :: String -> IPV4
makeIPV4 =  mapMaybe tryParse . splitOn "."

data RCODE = NoErr | FormatErr | ServFail | NameErr | NotImpl | Refused deriving (Eq, Show, Enum)

data RData = RDA IPV4
           | RDNS Domain
           | RDCName Domain
           | RDPtr Domain
   deriving (Show, Eq)

data DNSFlags = DNSFlags {
      flResp   :: !Bool
    , flOpcode :: !OpCode
    , flAa     :: !Bool
    , flTc     :: !Bool
    , flRd     :: !Bool
    , flRa     :: !Bool
    , flRcode  :: !RCODE
} deriving (Show, Eq)

data DNSHeader = DNSHeader {
       dnsID   :: !Word16
     , flags   :: !DNSFlags
     , qdcount :: !Int
     , ancount :: !Int
     , nscount :: !Int
     , arcount :: !Int
  } deriving (Show, Eq)

data DNSQuestion = DNSQuestion {
   qname  :: !Domain
 , qtype  :: !TYPE
 , qclass :: !Int
} deriving (Show, Eq)


data DNSResource = DNSResource {
    rname    :: !Domain
  , rtype    :: !TYPE
  , rclass   :: !Int
  , rttl     :: !Int
  , rdlength :: !Int
  , rdata    :: !RData
} deriving (Show, Eq)

data DNSPacket = DNSPacket {
   header     :: !DNSHeader
 , questions  :: ![DNSQuestion]
 , answers    :: ![DNSResource]
 , authority  :: ![DNSResource]
 , additional :: ![DNSResource]
} deriving (Show, Eq)

-- States for serialisation
data WState = WState {
    wsMap      :: M.Map Domain Int
  , wsPosition :: Int
}  deriving (Eq, Show)

data RState = RState {
    rsMap      :: IntMap Domain
  , rsPosition :: Int
} deriving (Eq, Show)

rstate :: RState
rstate = RState IM.empty 0

wstate :: WState
wstate = WState M.empty 0

-- StateT's for the above
type SGet a = S.StateT RState Get a
type SPut   = S.StateT WState PutM ()

