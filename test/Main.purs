module Test.Main where

import Prelude

import Effect (Effect)
import Effect.Class.Console (log)

main :: Effect Unit
main = do
  log "The tests are in the CTL repo: https://github.com/Plutonomicon/cardano-transaction-lib/"
