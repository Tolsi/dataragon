extern crate iui;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use heapless::consts::U16384;
use itertools::Itertools;
use iui::controls::{Button, Entry, GridAlignment, GridExpand, HorizontalSeparator, Label,
                    LayoutGrid, MultilineEntry, ProgressBar, Slider, Spinbox};
use iui::prelude::*;
use map_in_place::MapVecInPlace;
use structopt::StructOpt;

use dataragon::error::*;
use dataragon::objects::*;
use dataragon::serialization;

/// This struct will hold the values that multiple callbacks will need to access.
struct State {
    count: i32,
    threshold: i32,
    data: String,
    secretbox: String,
    shares: String,
}

fn split(secret: &String, count: u8, threshold: u8) -> Result<(String, Vec<String>)> {
    let text = secret.as_bytes();
    let allowed_data_damage_level = 1.0;

    dataragon::split(text, allowed_data_damage_level, count, threshold).and_then(|(shares, secret_box)| {
        let encoded_secret_box: heapless::Vec<u8, U16384> = postcard::to_vec(&secret_box).unwrap();
        return serialization::add_ecc_and_crc(encoded_secret_box.to_vec(), allowed_data_damage_level).map(|encoded_secret_box_with_ecc_and_crc| {
            (bs58::encode(encoded_secret_box_with_ecc_and_crc).into_string(), shares.map(|s| bs58::encode(s).into_string()))
        });
    })
}

fn combine(shares: Vec<String>, secretbox_string: &String) -> Result<String> {
    let secretbox = bs58::decode(secretbox_string).into_vec();
    let sb = serialization::try_to_read_stored_data(secretbox.unwrap().as_slice()).unwrap();
    let secret_box_bytes = sb.as_slice();
    let secret_box: CryptoSecretbox = postcard::from_bytes(&secret_box_bytes).unwrap();
    dataragon::combine(shares.map(|s| bs58::decode(s).into_vec().unwrap()), &secret_box).map(|r|
        String::from_utf8(r).unwrap())
}

fn main() {
    // Initialize the UI framework.
    let ui = UI::init().unwrap();

    // Initialize the state of the application.
    let state = Rc::new(RefCell::new(State { count: 2, threshold: 1, data: "".into(), secretbox: "".into(), shares: "".into() }));

    // Create the grid which we'll use to lay out controls
    let mut grid = LayoutGrid::new(&ui);
    grid.set_padded(&ui, true);

    // Set up the inputs for the application.
    // While it's not necessary to create a block for this, it makes the code a lot easier
    // to read; the indentation presents a visual cue informing the reader that these
    // statements are related.
    let (mut count_spinner, mut threshold_spinner, mut data_entry,
        mut secret_box_entry, mut shares_box_entry,
        mut split_button, mut combine_button) = {
        // Numerical inputs
        let spinner = Spinbox::new(&ui, 2, std::i32::MAX);
        let spinner2 = Spinbox::new(&ui, 1, std::i32::MAX);
        // Text inputs
        let entry = Entry::new(&ui);
        let multi = MultilineEntry::new(&ui);
        let multi2 = MultilineEntry::new(&ui);
        let split_button = Button::new(&ui, "Split");
        let combine_button = Button::new(&ui, "Combine");
        // Add everything into the grid
        grid.append(&ui, spinner.clone(),
                    // This is position (by slot) and size, expansion, and alignment.
                    // In this case, row 0, col 0, 1 by 1, compress as much as possible,
                    // and align to the fill.
                    0, 0, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, spinner2.clone(),
                    0, 1, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, HorizontalSeparator::new(&ui),
                    0, 2, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, entry.clone(),
                    0, 3, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, multi.clone(),
                    // The multiline entry is at column 0, row 1, and expands vertically.
                    0, 4, 1, 1, GridExpand::Both, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, multi2.clone(),
                    // The multiline entry is at column 0, row 1, and expands vertically.
                    0, 5, 1, 1, GridExpand::Both, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, split_button.clone(),
                    // The multiline entry is at column 0, row 1, and expands vertically.
                    0, 6, 2, 1, GridExpand::Vertical, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, combine_button.clone(),
                    // The multiline entry is at column 0, row 1, and expands vertically.
                    0, 7, 2, 1, GridExpand::Vertical, GridAlignment::Fill, GridAlignment::Fill);
        (spinner, spinner2, entry, multi, multi2, split_button, combine_button)
    };

    // Set up the outputs for the application. Organization is very similar to the
    // previous setup.
    let (add_label, sub_label, text_label, secretbox_label, shares_label) = {
        let add_label = Label::new(&ui, "");
        let sub_label = Label::new(&ui, "");
        let text_label = Label::new(&ui, "");
        let bigtext_label = Label::new(&ui, "");
        let bigtext2_label = Label::new(&ui, "");
        grid.append(&ui, add_label.clone(),
                    1, 0, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, sub_label.clone(),
                    1, 1, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        // We skip the #2 & 3 slots so that the text labels will align with their inputs.
        // This is important because the big text label can expand vertically.
        grid.append(&ui, text_label.clone(),
                    1, 3, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, bigtext_label.clone(),
                    1, 4, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        grid.append(&ui, bigtext2_label.clone(),
                    1, 5, 1, 1, GridExpand::Neither, GridAlignment::Fill, GridAlignment::Fill);
        (add_label, sub_label, text_label, bigtext_label, bigtext2_label)
    };

    // The window allows all constituent components to be displayed.
    let mut window = Window::new(&ui, "Dataragon UI", 500, 150, WindowType::NoMenubar);
    window.set_child(&ui, grid);
    window.show(&ui);

    // These on_changed functions allow updating the application state when a
    // control changes its value.

    count_spinner.on_changed(&ui, {
        let state = state.clone();
        move |val| { state.borrow_mut().count = val; }
    });

    threshold_spinner.on_changed(&ui, {
        let state = state.clone();
        move |val| { state.borrow_mut().threshold = val; }
    });

    data_entry.on_changed(&ui, {
        let state = state.clone();
        move |val| { state.borrow_mut().data = val; }
    });

    secret_box_entry.on_changed(&ui, {
        let state = state.clone();
        move |val| { state.borrow_mut().secretbox = val; }
    });

    shares_box_entry.on_changed(&ui, {
        let state = state.clone();
        move |val| { state.borrow_mut().shares = val; }
    });

    split_button.on_clicked(&ui, {
        let state = state.clone();
        move |v| {
            let (secret_box, shares) = split(&state.borrow().data, state.borrow().count as u8, state.borrow().threshold as u8).unwrap();
            state.borrow_mut().secretbox = secret_box;
            state.borrow_mut().shares = shares.join("\n");
        }
    });

    combine_button.on_clicked(&ui, {
        let ui = ui.clone();
        let state = state.clone();
        let mut data_entry = data_entry.clone();
        move |v| {
            let result = combine(state.borrow().shares.split('\n').map(|s| s.to_string()).collect_vec(), &state.borrow().secretbox).unwrap();
            data_entry.set_value(&ui, &result);
        }
    });


    // Rather than just invoking ui.run(), using EventLoop gives a lot more control
    // over the user interface event loop.
    // Here, the on_tick() callback is used to update the view against the state.
    let mut event_loop = ui.event_loop();
    event_loop.on_tick(&ui, {
        let ui = ui.clone();
        let mut add_label = add_label.clone();
        let mut sub_label = sub_label.clone();
        let mut text_label = text_label.clone();
        let mut secret_box_entry = secret_box_entry.clone();
        let mut shares_box_entry = shares_box_entry.clone();
        move || {
            let state = state.borrow();

            // Update all the outputs
            add_label.set_text(&ui, &format!("Count: {}", state.count));
            sub_label.set_text(&ui, &format!("Threshold: {}", state.threshold));
            text_label.set_text(&ui, &format!("Data: {}", state.data));
            secret_box_entry.set_value(&ui, &state.secretbox);
            shares_box_entry.set_value(&ui, &state.shares);
        }
    });
    event_loop.run(&ui);
}
