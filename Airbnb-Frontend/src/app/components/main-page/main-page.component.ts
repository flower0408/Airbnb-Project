import { Component, OnInit } from '@angular/core';
import {AccommodationService} from "../../services/accommodation.service";
import { Location } from '../../models/location.model';
import {Router} from "@angular/router";

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
  selector: 'app-main-page',
  templateUrl: './main-page.component.html',
  styleUrls: ['./main-page.component.css']
})
export class MainPageComponent implements OnInit {
  accommodations: Accommodation[] = [];
  locationFilter: string = '';
  minGuestsFilter: number | undefined;

  constructor(private accommodationService: AccommodationService, private router: Router,) {}

  ngOnInit(): void {
    this.getAccommodations();
  }

  getAccommodations(): void {
    this.accommodationService.getAllAccommodations().subscribe(
      (data) => {
        this.accommodations = data.sort((a: Accommodation, b: Accommodation) => {
          const idA = a.id ?? '';
          const idB = b.id ?? '';
          return idA > idB ? -1 : 1;
        });
        //console.log(data);
      },
      (error) => {
        console.error(error);
      }
    );
  }

  searchAccommodations(): void {

    const minGuests = this.minGuestsFilter !== undefined ? this.minGuestsFilter : 1;

    if (this.locationFilter || this.minGuestsFilter !== undefined) {
      this.accommodationService.searchAccommodations(this.locationFilter, minGuests).subscribe(
        (data: Accommodation[]) => {
          this.accommodations = data;
          this.locationFilter = '';
          this.minGuestsFilter = undefined;
        },
        (error) => {
          console.error(error);
        }
      );
    } else {
      this.getAccommodations();
      this.locationFilter = '';
      this.minGuestsFilter = undefined;
    }
  }
}
