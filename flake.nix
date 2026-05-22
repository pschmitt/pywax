{
  description = "pywax — Netgear WAX access point Python library and CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pyPackages = pkgs.python3Packages;
        pywax = pyPackages.buildPythonPackage {
          pname = "pywax";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [ pyPackages.hatchling ];
          dependencies = [
            pyPackages.rich
            pyPackages.rich-argparse
          ];
          pythonImportsCheck = [ "pywax" ];
        };
      in
      {
        packages.default = pywax;
        packages.pywax = pywax;
      }
    );
}
