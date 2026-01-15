// client/src/components/SeatMap.jsx
import React from 'react';

const Seat = ({ seat, isBusy, isHeld, isSelected, isHighlighted, isDimmed, isLimitReached, onSeatClick, mekanModu, guestCount, seatSize = 20 }) => {
  let className = 'seat';
  let isDisabled = false;

  // ⭐️ DÜZELTME: Title sadece masa adını içersin, "Koltuk" kelimesi geçmesin.
  let tooltipText = seat.label || seat.title || seat.id;

  const isRestoran = mekanModu === 'RESTORAN_AKILLI';

  if (isRestoran) {
    className += ' table-style'; // CSS için yeni sınıf

    if (seat.kapasite) {
      const max = seat.kapasite;
      const min = seat.min_kisi || 1;
      // Tooltip'te kapasiteyi göster
      tooltipText += ` (${min}-${max} Kişi)`;

      if (guestCount > max || guestCount < min) {
        className += ' capacity-mismatch';
        isDisabled = true;
      }
    }
  }

  // Durum Sınıfları
  if (isBusy) {
    className += ' busy';
    isDisabled = true;
    tooltipText += " (DOLU)";
  } else if (isSelected) {
    className += ' selected';
  } else if (isHeld) {
    className += ' held-by-others';
    isDisabled = true;
  } else if (!isRestoran && isLimitReached && !isSelected) {
    className += ' limit-reached';
  }

  // ⭐️ YENİ: Highlight (Vurgulama)
  if (isHighlighted) {
    className += ' admin-highlight';
  } else if (isDimmed) {
    // ⭐️ YENİ: Dimmed (Soluklaştırma)
    className += ' admin-dimmed';
  }

  // ⭐️ ŞEKİL SINIFI
  if (seat.shape === 'square' || seat.type === 'table-square') {
    className += ' square-shape';
  } else {
    className += ' round-shape';
  }

  return (
    <button
      type="button"
      className={className}
      style={{
        left: `${seat.x}%`,
        top: `${seat.y}%`,
        // ⭐️ RESPONSIVE BOYUTLANDIRMA
        // Dikdörtgen ise genişliği 2 katına çıkar
        width: seat.shape === 'rectangle' ? `${(seatSize / 8) * 2}%` : `${seatSize / 8}%`,
        height: 'auto',
        aspectRatio: seat.shape === 'rectangle' ? '2.5 / 1' : '1 / 1', // Dikdörtgen oranı

        marginLeft: `-${(seatSize / 8) / 2}%`,
        marginTop: `-${(seatSize / 8) / 2}%`,

        transform: 'none',
        maxWidth: 'none',
        minWidth: 'unset',
        // borderRadius class ile yönetiliyor
        backgroundColor: seat.id.startsWith('M-') ? 'var(--brand)' : undefined, // Opsiyonel masa rengi
      }}
      data-id={seat.id}
      title={tooltipText} // ⭐️ İsim sadece burada (hover) görünecek
      onClick={() => !isDisabled && onSeatClick(seat.id)}
      disabled={isDisabled}
    >
      {/* ⭐️ DÜZELTME: Butonun içi boşaltıldı, yazı yazmayacak */}
      <span className="sr-only">{tooltipText}</span>
    </button>
  );
};

// SeatMap Bileşeni
const SeatMap = ({
  allSeats,
  busySeats,
  heldSeats = [],
  selectedSeatIds,
  highlightedSeats = [], // ⭐️ YENİ: Vurgulanacak koltuklar
  guestCount,
  onSeatClick,
  mapStyle,
  mekanModu,
  seatSize = 20
}) => {

  if (allSeats.length === 0) {
    return (
      <div style={{ textAlign: 'center', color: 'var(--muted)', paddingTop: '50px' }}>
        Harita düzeni yüklenemedi.
      </div>
    );
  }

  const limitReached = selectedSeatIds.length >= guestCount;

  return (
    <div
      id="mapWrap"
      className="map-wrap"
      style={{
        backgroundImage: mapStyle.backgroundImage,
        aspectRatio: mapStyle.aspectRatio,
        backgroundSize: '100% 100%',
        backgroundRepeat: 'no-repeat',
        backgroundPosition: 'center'
      }}
    >
      {allSeats.map(seat => {
        const isBusy = busySeats.includes(seat.id);
        const isHeld = heldSeats.includes(seat.id) && !selectedSeatIds.includes(seat.id);
        const isSelected = selectedSeatIds.includes(seat.id);
        // ⭐️ YENİ: Vurgulama Kontrolü
        const isHighlighted = highlightedSeats.includes(seat.id);
        // ⭐️ YENİ: Dimmed (Soluk) Kontrolü
        // Eğer highlight edilen herhangi bir koltuk varsa, ve bu koltuk highlight değilse -> Dimmed
        const isDimmed = highlightedSeats.length > 0 && !isHighlighted;

        return (
          <Seat
            key={seat.id}
            seat={seat}
            isBusy={isBusy}
            isHeld={isHeld}
            isSelected={isSelected}
            isHighlighted={isHighlighted}
            isDimmed={isDimmed} // ⭐️ Prop olarak gönder
            isLimitReached={limitReached}
            onSeatClick={onSeatClick}
            mekanModu={mekanModu}
            guestCount={guestCount}
            seatSize={seatSize}
          />
        );
      })}
    </div>
  );
};

export default SeatMap;