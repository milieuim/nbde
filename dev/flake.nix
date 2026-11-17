{
  description = "partition. tests and dev cfg for nbde";

  inputs = {
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = _: { };
}
