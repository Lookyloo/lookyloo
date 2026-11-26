"use strict";
// Category tags: a category drawn as a MISP tag (js/components/misp_tag.js), like
// content-classification:cybercrime="phishing" -> |cybercrime phishing
// Used by the categories table (#categoriesTable, explore/categories.html).
//
// Front-end only: built from the JSON of POST /tables/categoriesTable/ (unchanged),
// whose category.display is a link rendered and escaped by Flask. It is parsed with
// DOMParser (inert), values are written back with textContent / attributes.
// Styles: css/components/tag.css. Doc: doc/ui/tags.md

// Tag element of a category: a MISP tag (js/components/misp_tag.js) with the colour of
// its type (website/web/category_colours.json). href: link to the captures of this
// category (or null)
function lkCategoryTag(sprite, category, href) {
    const tag = lkElement(href ? 'a' : 'span', 'lk-category-tag');
    if (href) {
        tag.href = href;
    }
    tag.title = category;
    tag.appendChild(lkMispTag(lkMispTagView(category, lkCategoryColour(category))));
    return tag;
}

// DataTables columns of #categoriesTable: [tag, machine tag, captures]
function lkCategoriesColumns(table) {
    const sprite = table.dataset.lkIcons;
    return [
        {
            data: {_: 'category.filter', filter: 'category.filter'},
            render: (data, type) => type === 'display' ? '' : data,
            createdCell: (cell, data, row) => {
                cell.appendChild(lkCategoryTag(sprite, row.category.display.category_name, row.category.display.category_url));
            },
        },
        {
            data: 'category.filter',
            orderable: false,
            // Phones: the tag already says it all
            visible: window.matchMedia('(min-width: 769px)').matches,
            render: (data, type) => type === 'display' ? '' : data,
            createdCell: (cell, data, row) => {
                cell.appendChild(lkElement('span', 'lk-machinetag', row.category.display.category_name));
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
