{-# LANGUAGE OverloadedStrings #-}
module Main  where

import           Control.Monad
import           Data.Binary
import           Data.Binary.Get
import qualified Data.ByteString            as B
import qualified Data.ByteString.Char8      as C8
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as L8
import           Data.List
import           Network.DNS
import           Test.QuickCheck

data DomainName = Domain String
    deriving (Show)

instance Arbitrary DomainName where
    arbitrary = do
        tld <- listOf1 $ elements ['a' .. 'z']
        domain <- elements [".com", ".co.uk", ".fr", ".de"]
        return $ Domain (tld ++ domain)

arbitraryRData :: TYPE -> Gen RData
arbitraryRData A = do
        a <- choose (1, 254)
        b <- choose (0, 254)
        c <- choose (0, 254)
        d <- choose (0, 254)
        return $ RDA [a, b, c, d]
arbitraryRData NS = do
       Domain dm <- arbitrary
       return $ RDNS (L8.pack dm)
arbitraryRData CNAME = do
       Domain dm <- arbitrary
       return $ RDCName (L8.pack dm)
arbitraryRData PTR = do
       Domain dm <- arbitrary
       return $ RDPtr (L8.pack dm)
arbitraryRData _ = do
       Domain dm <- arbitrary
       return $ RDPtr (L8.pack dm)

instance Arbitrary DNSFlags where
    arbitrary = do
        resp <- arbitrary
        aa <- arbitrary
        tc <- arbitrary
        rd <- arbitrary
        ra <- arbitrary
        rcode <- elements [ NoErr, FormatErr, ServFail, NameErr, NotImpl, Refused ]
        return $ DNSFlags resp Query aa tc rd ra rcode

instance Arbitrary DNSHeader where
   arbitrary = do
       Positive dnsId <- arbitrary
       flags    <- arbitrary
       qdcount  <- choose (0, 15)
       ancount  <- choose (0, 15)
       nscount  <- choose (0, 15)
       arcount  <- choose (0, 15)
       return $ DNSHeader dnsId flags qdcount ancount nscount arcount

instance Arbitrary DNSQuestion where
   arbitrary = do
       Domain qname <- arbitrary
       qtype <- elements [A, AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV]
       qclass <- choose (0, 10)
       return $ DNSQuestion (L8.pack qname) qtype qclass


validHeader :: Int -> Int -> DNSHeader -> Bool
validHeader ql rl (DNSHeader _ _ qdl rdl _ _) = ql == qdl && rl == rdl

instance Arbitrary DNSResource where
   arbitrary = do
        Domain rname <- arbitrary
        rtype <- elements [A, NS, CNAME, PTR]
        rclass <- choose (0, 65533)
        rttl <- choose (0, 65533)
        rdata <- arbitraryRData rtype
        let rLen  = rdLength rdata
        return $ DNSResource (L8.pack rname) rtype rclass rttl rLen rdata

instance Arbitrary DNSPacket where
    arbitrary = do
        questions <- listOf arbitrary
        answers <- listOf arbitrary
        authority <- listOf arbitrary
        additional <- listOf arbitrary
        header <- arbitrary -- (validHeader (length questions) 0)
        return $ DNSPacket header{ qdcount = length questions,
                                   ancount = length answers,
                                   nscount = length authority,
                                   arcount = length additional
                                 } questions answers authority additional

instance Arbitrary B.ByteString where
    arbitrary   = fmap B.pack arbitrary

instance Arbitrary Pointer where
    arbitrary = do
        ptr <- choose (1, 16382)
        return $ Pointer ptr ""

packUnpack :: String -> String
packUnpack str = L8.unpack $ runGet (getName []) input
  where
     input :: L8.ByteString
     input = packName $ L8.pack str

inu :: PBinary a => a -> a
inu a = runSGet $! runSPut a

propBin :: (PBinary a, Eq a, Arbitrary a) => a -> Bool
propBin a = a == b
   where b = runSGet $! runSPut a

prop_binaryflags :: DNSFlags -> Bool
prop_binaryflags = propBin

prop_dnsHeader :: DNSHeader -> Bool
prop_dnsHeader = propBin

prop_dnsQuestion :: DNSQuestion -> Bool
prop_dnsQuestion = propBin

prop_dnsPacket :: DNSPacket -> Bool
prop_dnsPacket = propBin

prop_dnsResource :: DNSResource -> Bool
prop_dnsResource = propBin

prop_packer :: DomainName -> Bool
prop_packer (Domain d) = d == packUnpack d

prop_pointer :: Pointer -> Bool
prop_pointer = propBin

main :: IO ()
main = do
     quickCheck prop_dnsQuestion
     quickCheck prop_dnsResource
     quickCheck prop_binaryflags
     quickCheck prop_dnsHeader
     quickCheck prop_packer
     quickCheck prop_dnsPacket
     quickCheck prop_pointer

