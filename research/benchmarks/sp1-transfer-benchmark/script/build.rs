use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    let mut args = BuildArgs::default();
    args.docker = true;
    build_program_with_args("../program", args)
}
