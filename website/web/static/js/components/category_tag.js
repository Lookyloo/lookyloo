"use strict";
// Category tags: a category as a coloured pill with an icon, like
// content-classification:cybercrime="phishing" -> [bug] cybercrime · phishing
// Used by the categories table (#categoriesTable, explore/categories.html).
//
// Front-end only: built from the JSON of POST /tables/categoriesTable/ (unchanged),
// whose category.display is a link rendered and escaped by Flask. It is parsed with
// DOMParser (inert), values are written back with textContent / attributes.
// Styles: css/components/tag.css. Doc: doc/ui/tags.md

// Family of the MISP taxonomy -> [tint, Bootstrap icon]
const LK_CATEGORY_FAMILIES = {
    'general': ['blue', 'newspaper'],
    'technology': ['teal', 'cpu'],
    'technical-services': ['teal', 'hdd-stack'],
    'cybersecurity': ['green', 'shield-check'],
    'cybercrime': ['red', 'bug'],
    'illegal-markets': ['red', 'cart-x'],
    'markets': ['amber', 'cart'],
    'finance': ['amber', 'bank'],
    'communities': ['pink', 'people'],
    'digital-content': ['violet', 'play-btn'],
    'geopolitics-and-hacktivism': ['violet', 'flag'],
};
const LK_CATEGORY_TAG = /^(?<namespace>[^:]+):(?<family>[^=]+)="?(?<value>[^"]*)"?$/;

// Tag element of a category. href: link to the captures of this category (or null)
function lkCategoryTag(sprite, category, href) {
    let tint = 'slate';
    let iconName = 'tag';
    let family = '';
    let label = category;
    const match = LK_CATEGORY_TAG.exec(category);
    if (match) {
        family = match.groups.family;
        label = match.groups.value.replaceAll('-', ' ');
        [tint, iconName] = LK_CATEGORY_FAMILIES[family] || [tint, iconName];
    }
    const tag = lkElement(href ? 'a' : 'span', `lk-tag lk-tag-${tint}`);
    if (href) {
        tag.href = href;
    }
    tag.title = category;
    tag.appendChild(lkIcon(sprite, iconName));
    if (family) {
        tag.appendChild(lkElement('span', 'lk-tag-family', family.replaceAll('-', ' ')));
    }
    tag.appendChild(lkElement('span', null, label));
    return tag;
}

// DataTables columns of #categoriesTable: [tag, machine tag, captures]
function lkCategoriesColumns(table) {
    const sprite = table.dataset.lkIcons;
    const parse = row => {
        const link = lkParseFragment(row.category.display).querySelector('a[href]');
        return {category: link ? link.textContent : '', href: link ? link.getAttribute('href') : null};
    };
    return [
        {
            data: {_: 'category.filter', filter: 'category.filter'},
            render: (data, type) => type === 'display' ? '' : data,
            createdCell: (cell, data, row) => {
                const {category, href} = parse(row);
                cell.appendChild(lkCategoryTag(sprite, category, href));
            },
        },
        {
            data: 'category.filter',
            orderable: false,
            // Phones: the tag already says it all
            visible: window.matchMedia('(min-width: 769px)').matches,
            render: (data, type) => type === 'display' ? '' : data,
            createdCell: (cell, data, row) => {
                cell.appendChild(lkElement('span', 'lk-machinetag', parse(row).category));
            },
        },
        {data: 'total_captures', orderable: true, className: 'lk-categories-count'},
    ];
}

// Category filter of the captures list (home/index.html, #lk-index-filters): the
// same tag as on the categories page, with a cross removing the filter. Returned
// as a node for the DataTables layout (next to "per page"), the server-rendered
// chip is removed. null when there is no filter.
function lkIndexFilter(sprite) {
    const filters = document.getElementById('lk-index-filters');
    if (!filters || !filters.dataset.category) {
        return null;
    }
    const remove = filters.querySelector('[data-lk-remove-filter]');
    const wrapper = lkElement('div', 'lk-active-filter');
    wrapper.appendChild(lkCategoryTag(sprite, filters.dataset.category, null));
    if (remove) {
        const link = lkElement('a', 'lk-active-filter-remove');
        link.href = remove.getAttribute('href');
        link.title = 'Remove the filter';
        link.setAttribute('aria-label', 'Remove the category filter');
        link.appendChild(lkIcon(sprite, 'x-lg'));
        wrapper.appendChild(link);
    }
    filters.remove();
    return wrapper;
}
