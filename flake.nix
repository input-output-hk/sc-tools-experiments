{
  description = "sc-tools";

  inputs = {

    haskell-nix = {
      url = "github:input-output-hk/haskell.nix";
      inputs.hackage.follows = "hackage";
    };

    # Using nixpkgs 24.11 which has ghc945 needed for haskell.nix bootstrap
    # used as in the `sc-tools` repo
    nixpkgs.follows = "haskell-nix/nixpkgs-2411";

    hackage = {
      url = "github:input-output-hk/hackage.nix";
      flake = false;
    };

    CHaP = {
      url = "github:IntersectMBO/cardano-haskell-packages?ref=repo";
      flake = false;
    };

    iohk-nix = {
      url = "github:input-output-hk/iohk-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";

    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };

    systems.url = "github:nix-systems/default";
  };


  # NOTE: nix flake show --override-input systems github:nix-systems/x86_64-linux
  outputs = inputs: inputs.flake-utils.lib.eachDefaultSystem (system:
    import ./nix/outputs.nix { inherit inputs system; }
  );

  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      "https://sc-testing-tools.cachix.org"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "sc-testing-tools.cachix.org-1:EdJM0ldUx5PeP16xc1fjZ5oCGgryZJxf/Q1MHQ40M8s="
    ];
    allow-import-from-derivation = true;
    accept-flake-config = true;
  };
}
