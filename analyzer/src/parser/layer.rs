pub struct Layer<'a> {
    name: &'static str,
    metadatas: Vec<Metadata<'a>>,
}

impl<'a> Layer<'a> {
    pub fn new() {}
}

pub struct Metadata<'a> {
    name: &'static str,
    data: &'a [u8],
}
