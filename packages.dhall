let upstream =
      https://github.com/purescript/package-sets/releases/download/psc-0.15.10-20231023/packages.dhall
        sha256:b9a482e743055ba8f2d65b08a88cd772b59c6e2084d0e5ad854025fa90417fd4

let additions =
      { aeson =
        { dependencies =
          [ "aff"
          , "argonaut"
          , "argonaut-codecs"
          , "argonaut-core"
          , "arrays"
          , "bifunctors"
          , "const"
          , "control"
          , "effect"
          , "either"
          , "exceptions"
          , "foldable-traversable"
          , "foreign-object"
          , "integers"
          , "js-bigints"
          , "lists"
          , "maybe"
          , "mote"
          , "numbers"
          , "ordered-collections"
          , "partial"
          , "prelude"
          , "quickcheck"
          , "record"
          , "spec"
          , "strings"
          , "tuples"
          , "typelevel"
          , "typelevel-prelude"
          , "uint"
          , "untagged-union"
          ]
        , repo = "https://github.com/mlabs-haskell/purescript-aeson.git"
        , version = "v2.0.0"
        }
      , properties =
        { dependencies = [ "prelude", "console" ]
        , repo = "https://github.com/Risto-Stevcev/purescript-properties.git"
        , version = "v0.2.0"
        }
      , lattice =
        { dependencies = [ "prelude", "console", "properties" ]
        , repo = "https://github.com/Risto-Stevcev/purescript-lattice.git"
        , version = "v0.3.0"
        }
      , bytearrays =
        { dependencies =
          [ "aeson"
          , "aff"
          , "arraybuffer-types"
          , "effect"
          , "either"
          , "foldable-traversable"
          , "maybe"
          , "newtype"
          , "prelude"
          , "quickcheck"
          , "quickcheck-laws"
          , "spec"
          , "strings"
          ]
        , repo = "https://github.com/mlabs-haskell/purescript-bytearrays"
        , version = "e3991d562a04d8825472551d91a06407ad9c9112"
        }
      , cardano-serialization-lib =
        { dependencies =
          [ "aeson"
          , "argonaut"
          , "bifunctors"
          , "bytearrays"
          , "effect"
          , "either"
          , "maybe"
          , "nullable"
          , "ordered-collections"
          , "prelude"
          , "profunctor"
          , "tuples"
          ]
        , repo =
            "https://github.com/mlabs-haskell/purescript-cardano-serialization-lib"
        , version = "fcc1af0e69619e9911d284fc79ca26a50b686ff9"
        }
      , cardano-plutus-data-schema =
        { dependencies = [ "prelude" ]
        , repo =
            "https://github.com/mlabs-haskell/purescript-cardano-plutus-data-schema"
        , version = "351003d931990949ce3d73f399a179e4a0fa40f1"
        }
      , cardano-types =
        { dependencies =
          [ "aeson"
          , "arraybuffer-types"
          , "arrays"
          , "bifunctors"
          , "bytearrays"
          , "cardano-plutus-data-schema"
          , "cardano-serialization-lib"
          , "console"
          , "control"
          , "effect"
          , "either"
          , "encoding"
          , "exceptions"
          , "foldable-traversable"
          , "foreign-object"
          , "integers"
          , "js-bigints"
          , "lattice"
          , "lists"
          , "literals"
          , "maybe"
          , "monad-logger"
          , "newtype"
          , "nonempty"
          , "nullable"
          , "ordered-collections"
          , "partial"
          , "prelude"
          , "profunctor"
          , "quickcheck"
          , "rationals"
          , "record"
          , "safe-coerce"
          , "strings"
          , "these"
          , "tuples"
          , "typelevel-prelude"
          , "uint"
          , "unfoldable"
          , "unsafe-coerce"
          ]
        , repo = "https://github.com/mlabs-haskell/purescript-cardano-types"
        , version = "dc3538e532ffcca4cea7548cc6967d0b56e169a5"
        }
      }

in  upstream // additions
