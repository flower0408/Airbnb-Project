import { Component, OnInit } from '@angular/core';
import {ActivatedRoute, Router} from '@angular/router';
import {Location} from "../../models/location.model";
import {AccommodationService} from "../../services/accommodation.service";

interface Accommodation {
  id?: string;
  name: string;
  description?: string;
  images: string;
  location: Location;
  benefits: string;
  minGuest: number;
  maxGuest: number;
  ownerId: string;
}

@Component({
  selector: 'app-accommodation-details',
  templateUrl: './accommodation-details.component.html',
  styleUrls: ['./accommodation-details.component.css']
})
export class AccommodationDetailsComponent implements OnInit {
  accommodation: Accommodation | null = null;

  constructor(private accommodationService: AccommodationService, private route: ActivatedRoute) {}


  ngOnInit(): void {
    this.getAccommodationById();
  }

  getAccommodationById(): void {
    const accommodationId = this.route.snapshot.paramMap.get('id');
    if (accommodationId) {
      this.accommodationService.getAccommodationById(accommodationId).subscribe(
        (data: Accommodation) => {
          this.accommodation = data;
        },
        (error) => {
          console.error(error);
        }
      );
    }
  }


}
