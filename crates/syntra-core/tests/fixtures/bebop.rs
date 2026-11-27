// Assemble raw fields so malformed/boundary inputs don't go through a validating encoder.
pub fn sized(bytes: &[u8]) -> Vec<u8> {
    [
        &u32::try_from(bytes.len()).unwrap().to_le_bytes()[..],
        bytes,
    ]
    .concat()
}

pub fn union(tag: u8, body: &[u8]) -> Vec<u8> {
    [
        &u32::try_from(body.len()).unwrap().to_le_bytes()[..],
        &[tag],
        body,
    ]
    .concat()
}

pub fn frame(version: u32, id: u64, tag: u8, body: &[u8]) -> Vec<u8> {
    [
        &version.to_le_bytes()[..],
        &id.to_le_bytes(),
        &union(tag, body),
    ]
    .concat()
}

pub fn field_frame(tag: u8, value: &[u8]) -> Vec<u8> {
    let sized_value = sized(value);
    let (id, message) = match tag {
        10 => (
            0,
            [&[1, 1, 0, 0, 0, 2, 1, 0, 0, 0, 3][..], &sized_value, &[0]].concat(),
        ),
        11 | 15 => (0, [&[1][..], &sized_value, &[0]].concat()),
        12 => (7, [&[1][..], &sized_value, &[0]].concat()),
        13 => (7, [&[1, 13, 0, 0, 0, 2][..], &sized_value, &[0]].concat()),
        _ => unreachable!(),
    };
    let mut body = sized(&message);
    if tag == 13 {
        body = union(2, &body);
    }
    frame(1, id, tag, &body)
}
