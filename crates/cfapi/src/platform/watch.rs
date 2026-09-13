//! The basket watch: the one direction that leads out of the folder into the program.
//!
//! cfAPI reports no creation — [`crate::intake`] says why there is a beat here and not a directory
//! watch. Every round reads the basket directories and hands over what lies in them; the engine
//! drops what it already has, so a second announcement of the same file costs nothing.
//!
//! **What the map knows, and what it does not.** The map learns a basket when Windows fetches the
//! listing of the baskets container — that is, when somebody has looked. After a start of the
//! program nobody has looked yet, and a file dropped in yesterday would lie there until the user
//! opens the folder. That is what [`prime`] is for: the source is asked for the same listing
//! Explorer would get, only without Explorer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use edms_core::identifier::BasketIdentifier;
use edms_core::namespace::{Container, EntryIdentifier};

use crate::intake::{Beat, LOOK_AGAIN, basket_directories, dropped_in};
use crate::path::connect;

use super::Inner;
use super::win;

/// How long the watch waits before asking the source about the baskets a second time.
///
/// It asks only while the map knows no basket at all. Offline every attempt is a failed round trip
/// through the engine, and a minute is the distance at which that costs nothing — a file lying in
/// a basket is not lost meanwhile, it is announced as soon as somebody opens the folder.
pub(crate) const ASK_AGAIN: Duration = Duration::from_secs(60);

/// Starts the watch of this connection; it ends when the returned beat is dropped.
pub(crate) fn start(inner: &Arc<Inner>) -> Beat {
    let inner = Arc::clone(inner);
    // The state of the watch and of nobody else: it lives in the closure, so that no second thread
    // can ask what this one has already asked.
    let mut asked: Option<Instant> = None;
    Beat::start(LOOK_AGAIN, move || {
        let mut baskets = basket_directories(&inner.map());
        if baskets.is_empty() && asked.is_none_or(|when| when.elapsed() >= ASK_AGAIN) {
            asked = Some(Instant::now());
            prime(&inner);
            baskets = basket_directories(&inner.map());
        }
        for (basket, relative) in baskets {
            look_into(&inner, basket, &relative);
        }
    })
}

/// Enters the baskets the source names into the map — only those that are there on disk.
///
/// **Not** marked as populated: whether Windows has fetched a listing is a statement about
/// Explorer, and this is not Explorer. Without the mark `report_change` leaves the container alone
/// and Windows fetches the listing itself the next time it is opened
/// ([`crate::path_map::PathMap::is_populated`]).
///
/// A basket whose directory is not there is passed over. It would be a basket the server knows and
/// Explorer has never shown — nothing can lie in a directory that does not exist, and an entry in
/// the map for a path that is not there would be a claim nobody has checked.
fn prime(inner: &Inner) {
    let baskets = EntryIdentifier::Container(Container::Baskets);
    let root_children = match inner.source.children(Container::Root) {
        Ok(children) => children,
        Err(error) => {
            tracing::debug!(%error, "the root listing for the basket watch did not arrive");
            return;
        }
    };
    let Some(name) = root_children.into_iter().find(|e| e.identifier == baskets).map(|e| e.name)
    else {
        tracing::warn!("the root listing carries no basket container");
        return;
    };
    let directory = connect(&inner.root, &name);
    if !win::present(&directory) {
        return;
    }
    let children = match inner.source.children(Container::Baskets) {
        Ok(children) => children,
        Err(error) => {
            tracing::debug!(%error, "the basket listing for the watch did not arrive");
            return;
        }
    };
    // Which container takes files is `edms_core`'s answer and not this crate's (namespace v2 §3)
    // — whatever else may stand in this listing is none of the watch's business. Asked before the
    // lock is taken: a callback must not wait on the map while this thread asks the file system.
    let there: Vec<(EntryIdentifier, bool, String)> = children
        .into_iter()
        .filter(|entry| entry.identifier.container().is_some_and(Container::accepts_new_files))
        .filter(|entry| win::present(&connect(&directory, &entry.name)))
        .map(|entry| (entry.identifier, entry.is_folder(), entry.name))
        .collect();
    let mut map = inner.map();
    map.set(baskets, &name, true);
    for (identifier, folder, title) in there {
        map.set(identifier, &title, folder);
    }
}

/// Announces everything that lies in one basket.
fn look_into(inner: &Inner, basket: BasketIdentifier, relative: &str) {
    let directory = connect(&inner.root, relative);
    // A directory that is not there yields an empty listing (`win::read_directory`): a basket that
    // has been renamed or removed on the server since the map learned it is not an error here —
    // the next listing puts the map right.
    let found = match win::read_directory(&directory) {
        Ok(found) => found,
        Err(error) => {
            tracing::debug!(%relative, %error, "a basket could not be read");
            return;
        }
    };
    let names: Vec<String> =
        dropped_in(&inner.map(), basket, &found).into_iter().map(str::to_owned).collect();
    for name in names {
        // The map's lock is gone by now: `file_appeared` goes into the engine, and no callback
        // should have to wait behind it for the path map.
        inner.intake.file_appeared(basket, &connect(&directory, &name));
    }
}
