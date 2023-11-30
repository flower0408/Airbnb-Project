import { Component, OnInit } from '@angular/core';
import {AccommodationService} from "../../services/accommodation.service";
import {FormBuilder, FormGroup, Validators} from "@angular/forms";

// Define the type for Accommodation
interface Location {
  country: string;
  city: string;
  street: string;
  number: number;
}

interface Accommodation {
  id: string;
  name: string;
  description: string;
  images: string;
  benefits: string;
  minGuest: number;
  maxGuest: number;
  location: Location;
}

@Component({
  selector: 'app-main-page',
  templateUrl: './main-page.component.html',
  styleUrls: ['./main-page.component.css']
})
export class MainPageComponent implements OnInit {
  accommodations: any[] = [];

  constructor(private accommodationService: AccommodationService) {}

  ngOnInit(): void {
    this.getAccommodations();
  }

  getAccommodations(): void {
    this.accommodationService.getAllAccommodations().subscribe(
      (data) => {
        this.accommodations = data.sort((a: Accommodation, b: Accommodation) => (a.id > b.id ? -1 : 1));
        //console.log(data);
      },
      (error) => {
        console.error(error);
      }
    );
  }
}
