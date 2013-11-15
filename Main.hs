module Main where

import           Control.Concurrent
import           Network.DNS

main :: IO ()
main = do
    forkIO (dnsServer 53 resolvConf)
    putStrLn "Return to quit"
    _ <- getLine
    putStrLn "Quitting...."
    return ()
  where
     resolvConf = dnsMapResolver [("0x0.io"      , "2.2.2.2"),
                                  ("google.com"  , "9.9.9.9")]


