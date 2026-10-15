pub struct Object;

pub trait Serializable {
    fn serialize(&self) -> Object;
}
