pub struct Layer<'a> {
    name: &'static str,
    metadatas: Vec<Metadata<'a>>,
}

pub struct Metadata<'a> {
    name: &'static str,
    data: &'a [u8],
}
