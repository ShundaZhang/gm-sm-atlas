(() => {
  const search = document.getElementById('tool-search');
  const category = document.getElementById('tool-category');
  const cards = [...document.querySelectorAll('.tool-card')];
  const zh = document.documentElement.lang.startsWith('zh');
  function filter() {
    const query = search.value.trim().toLocaleLowerCase();
    let count = 0;
    cards.forEach(card => {
      const visible = (category.value === 'all' || card.dataset.category === category.value) && card.textContent.toLocaleLowerCase().includes(query);
      card.hidden = !visible;
      if (visible) count++;
    });
    document.getElementById('tool-count').textContent = zh ? `${count} / ${cards.length} 项资源` : `${count} / ${cards.length} resources`;
    document.getElementById('tool-empty').hidden = count !== 0;
  }
  search.addEventListener('input', filter);
  category.addEventListener('change', filter);
  filter();
})();
